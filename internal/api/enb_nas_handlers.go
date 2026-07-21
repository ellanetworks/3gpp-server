// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

// TS 24.301 §9.9.3.21.
const ksiNoKey uint8 = 7

// TS 36.413 §9.2.1.3.
const causeRadioNetworkUnspecified = 0

// TS 24.301 §9.9.3.9.
const (
	emmCauseMACFailure   uint8 = 20
	emmCauseSynchFailure uint8 = 21
	emmCauseNonEPS       uint8 = 26
)

func attachOverrides(req *SendENBUES1APRequest) *naseps.AttachRequestOverrides {
	return &naseps.AttachRequestOverrides{
		UENetworkCapability:             req.UENetworkCapabilityOverride,
		OldPTMSISignature:               req.OldPTMSISignature,
		AdditionalGUTI:                  req.AdditionalGUTI,
		LastVisitedRegisteredTAI:        req.LastVisitedRegisteredTAI,
		DRXParameter:                    req.DRXParameter,
		MSNetworkCapability:             req.MSNetworkCapability,
		OldLocationAreaID:               req.OldLocationAreaID,
		TMSIStatus:                      req.TMSIStatus,
		MobileStationClassmark2:         req.MobileStationClassmark2,
		MobileStationClassmark3:         req.MobileStationClassmark3,
		SupportedCodecs:                 req.SupportedCodecs,
		AdditionalUpdateType:            req.AdditionalUpdateType,
		VoiceDomainPreference:           req.VoiceDomainPreference,
		DeviceProperties:                req.DeviceProperties,
		OldGUTIType:                     req.OldGUTIType,
		MSNetworkFeatureSupport:         req.MSNetworkFeatureSupport,
		TMSIBasedNRIContainer:           req.TMSIBasedNRIContainer,
		T3324Value:                      req.T3324Value,
		T3412ExtendedValue:              req.T3412ExtendedValue,
		ExtendedDRXParameters:           req.ExtendedDRXParameters,
		UEAdditionalSecurityCapability:  req.UEAdditionalSecurityCapability,
		UEStatus:                        req.UEStatus,
		AdditionalInformationRequested:  req.AdditionalInformationRequested,
		N1UENetworkCapability:           req.N1UENetworkCapability,
		UERadioCapabilityIDAvailability: req.UERadioCapabilityIDAvailability,
		RequestedWUSAssistance:          req.RequestedWUSAssistance,
		DRXParameterNBS1Mode:            req.DRXParameterNBS1Mode,
		RequestedIMSIOffset:             req.RequestedIMSIOffset,
	}
}

func handleENBAttachRequest(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if req.RawNASPDU != nil {
		return handleENBAttachRequestRaw(ctx, enb, ue, t, *req.RawNASPDU, req.RRCEstablishmentCauseOverride)
	}

	pdnType := req.PDNType
	if pdnType == 0 {
		pdnType = naseps.PDNTypeIPv4
	}

	esm, err := naseps.BuildPDNConnectivityRequest(1, pdnType)
	if err != nil {
		return nil, err
	}

	params := naseps.AttachRequestParams{
		IMSI:                ue.IMSI,
		AttachType:          req.AttachType,
		NASKeySetIdentifier: ksiNoKey,
		UENetworkCapability: ue.UENetworkCapability,
		ESMContainer:        esm,
		Overrides:           attachOverrides(req),
	}

	if req.ForeignGUTI {
		params.GUTI = &naseps.GUTIParams{MCC: enb.MCC, MNC: enb.MNC, MMEGroupID: 1, MMECode: 1, MTMSI: 0x0BADF00D}
	}

	ar, err := naseps.BuildAttachRequest(params)
	if err != nil {
		return nil, err
	}

	init, err := s1ap.BuildInitialUEMessage(s1ap.InitialUEMessageParams{
		ENBUES1APID: ue.ENBUES1APID, NASPDU: ar, MCC: enb.MCC, MNC: enb.MNC, TAC: enb.TAC, CellID: 1,
		RRCEstablishmentCause: req.RRCEstablishmentCauseOverride,
	})
	if err != nil {
		return nil, err
	}

	if err := t.Send(init, false); err != nil {
		return nil, err
	}

	dl, err := waitDownlink(ctx, t, ue, "DownlinkNASTransport")
	if err != nil {
		return nil, err
	}

	learnMMEID(ue, dl)

	plain, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateENBSecurityHeaderType(nas, plain)

	ue.RAND, _ = hex.DecodeString(nas.RAND)
	ue.AUTN, _ = hex.DecodeString(nas.AUTN)
	if nas.NASKeySetIdentifier != nil {
		ue.KSI = uint8(*nas.NASKeySetIdentifier)
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

func handleENBAttachRequestRaw(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, rawHex string, rrcCause *int64) (*SendENBUES1APResponse, error) {
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "raw_nas_pdu must be hex: %v", err)
	}

	init, err := s1ap.BuildInitialUEMessage(s1ap.InitialUEMessageParams{
		ENBUES1APID: ue.ENBUES1APID, NASPDU: raw, MCC: enb.MCC, MNC: enb.MNC, TAC: enb.TAC, CellID: 1,
		RRCEstablishmentCause: rrcCause,
	})
	if err != nil {
		return nil, err
	}

	if err := t.Send(init, false); err != nil {
		return nil, err
	}

	dl := waitDownlinkTolerant(ctx, t, ue, "DownlinkNASTransport", "UEContextReleaseCommand", "ErrorIndication")
	if dl == nil {
		return &SendENBUES1APResponse{}, nil
	}

	learnMMEID(ue, dl)

	var nas *naseps.NASResponse
	if dl.NASPDU != nil {
		if plain, perr := nasPDUBytes(dl); perr == nil {
			nas, _ = naseps.Decode(plain)
			annotateENBSecurityHeaderType(nas, plain)
		}
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

func handleENBAuthenticationResponse(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	aka, err := crypto.ComputeEPSAKA(ue.K, ue.OPc, ue.SQN, enb.MCC, enb.MNC, ue.RAND, ue.AUTN)
	if err != nil {
		return nil, fmt.Errorf("eps-aka: %w", err)
	}

	ue.Kasme = aka.Kasme

	res := aka.RES
	if req.RESOverride != nil {
		if res, err = hex.DecodeString(*req.RESOverride); err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "res_override must be hex: %v", err)
		}
	}

	pdu, err := naseps.BuildAuthenticationResponse(res)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, pdu, req); err != nil {
		return nil, err
	}

	dl, err := waitDownlink(ctx, t, ue, "DownlinkNASTransport")
	if err != nil {
		return nil, err
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	nasResp, macVerified := decodeENBDownlinkNAS(ue, nasBytes)

	return &SendENBUES1APResponse{S1AP: dl, NAS: nasResp, MACVerified: macVerified}, nil
}

func handleENBIdentityResponse(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	pdu, err := naseps.BuildIdentityResponse(ue.IMSI)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, pdu, req); err != nil {
		return nil, err
	}

	dl, err := waitDownlinkReq(ctx, t, ue, req, "DownlinkNASTransport", "ErrorIndication")
	if err != nil {
		return nil, err
	}

	if dl.NASPDU == nil {
		return &SendENBUES1APResponse{S1AP: dl}, nil
	}

	plain, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateENBSecurityHeaderType(nas, plain)

	if nas.MessageType == "authentication_request" {
		ue.RAND, _ = hex.DecodeString(nas.RAND)
		ue.AUTN, _ = hex.DecodeString(nas.AUTN)
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

func handleENBAuthenticationFailure(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if req.Cause == nil {
		return nil, httpErrorf(http.StatusBadRequest, "cause is required for authentication_failure")
	}

	cause := uint8(*req.Cause)

	var auts []byte
	if cause == emmCauseSynchFailure {
		var err error
		if auts, err = crypto.ComputeAUTS(ue.K, ue.OPc, ue.SQN, ue.RAND); err != nil {
			return nil, fmt.Errorf("compute AUTS: %w", err)
		}
	}

	pdu, err := naseps.BuildAuthenticationFailure(cause, auts)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, pdu, req); err != nil {
		return nil, err
	}

	dl, err := waitDownlinkReq(ctx, t, ue, req, "DownlinkNASTransport", "ErrorIndication")
	if err != nil {
		return nil, err
	}

	if dl.NASPDU == nil {
		return &SendENBUES1APResponse{S1AP: dl}, nil
	}

	plain, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateENBSecurityHeaderType(nas, plain)

	if nas.MessageType == "authentication_request" {
		ue.RAND, _ = hex.DecodeString(nas.RAND)
		ue.AUTN, _ = hex.DecodeString(nas.AUTN)
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

func handleENBSecurityModeComplete(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, fmt.Errorf("no NAS security context; run authentication_response first")
	}

	smc, err := naseps.BuildSecurityModeComplete(ue.IMEISV)
	if err != nil {
		return nil, err
	}

	protected, err := encodeENBUplinkNAS(ue, smc, naseps.SHTIntegrityProtectedCiphered, req)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	if req.CorruptMAC {
		return &SendENBUES1APResponse{S1AP: waitDownlinkTolerantReq(ctx, t, ue, req, "InitialContextSetupRequest")}, nil
	}

	dl, err := waitDownlinkReq(ctx, t, ue, req, "InitialContextSetupRequest", "ErrorIndication")
	if err != nil {
		return nil, err
	}

	if dl.NASPDU == nil {
		return &SendENBUES1APResponse{S1AP: dl}, nil
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	nas, macVerified := decodeENBDownlinkNAS(ue, nasBytes)
	if nas == nil {
		return &SendENBUES1APResponse{S1AP: dl, MACVerified: macVerified}, nil
	}

	if nas.EPSBearerIdentity != nil {
		ue.EPSBearerID = uint8(*nas.EPSBearerIdentity)
	}

	if nas.BearerPTI != nil {
		ue.PTI = uint8(*nas.BearerPTI)
	}

	if nas.GUTI != nil {
		ue.GUTIMCC = nas.GUTI.MCC
		ue.GUTIMNC = nas.GUTI.MNC
		ue.GUTIGroupID = uint16(nas.GUTI.MMEGroupID)
		ue.GUTICode = uint8(nas.GUTI.MMECode)

		if v, perr := strconv.ParseUint(nas.GUTI.MTMSI, 16, 32); perr == nil {
			ue.GUTIMTMSI = uint32(v)
		}
	}

	if len(dl.ERABSetupItems) > 0 {
		e := dl.ERABSetupItems[0]
		ue.ERABID = uint8(e.ERABID)
		ue.ULTeid = e.GTPTEID
		ue.SGWIP = erabSGWIP(enb, e)
	}

	ue.DLTeid = ue.ENBUES1APID
	ue.UEIP = ueIPFromPDNAddress(nas.PDNAddress)

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas, MACVerified: macVerified}, nil
}

func ueIPFromPDNAddress(pdnHex string) string {
	b, err := hex.DecodeString(pdnHex)
	if err != nil || len(b) < 5 || b[0] != naseps.PDNTypeIPv4 {
		return ""
	}

	return net.IP(b[1:5]).String()
}

func handleENBSecurityModeReject(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	cause := emmCauseSecurityCapMismatch
	if req.Cause != nil {
		cause = uint8(*req.Cause)
	}

	pdu, err := naseps.BuildSecurityModeReject(cause)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, pdu, req); err != nil {
		return nil, err
	}

	dl, err := waitDownlinkReq(ctx, t, ue, req, "UEContextReleaseCommand", "ErrorIndication")
	if err != nil {
		return nil, err
	}

	return &SendENBUES1APResponse{S1AP: dl}, nil
}

func handleENBAttachComplete(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	icsResp, err := s1ap.BuildInitialContextSetupResponse(s1ap.InitialContextSetupResponseParams{
		MMEUES1APID: ue.MMEUES1APID, ENBUES1APID: ue.ENBUES1APID,
		ERABID: ue.ERABID, ENBN3Addr: enb.N3Addr, GTPTEID: ue.ENBUES1APID,
	})
	if err != nil {
		return nil, err
	}

	if err := t.Send(icsResp, false); err != nil {
		return nil, err
	}

	esm, err := naseps.BuildActivateDefaultEPSBearerContextAccept(ue.EPSBearerID, ue.PTI)
	if err != nil {
		return nil, err
	}

	ac, err := naseps.BuildAttachComplete(esm)
	if err != nil {
		return nil, err
	}

	protected, err := encodeENBUplinkNAS(ue, ac, naseps.SHTIntegrityProtectedCiphered, nil)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	// Consuming the optional EMM Information keeps the downlink NAS COUNT in step.
	wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	resp := &SendENBUES1APResponse{}

	if dl := waitDownlinkTolerantReq(wctx, t, ue, req, "DownlinkNASTransport", "ErrorIndication"); dl != nil {
		resp.S1AP = dl

		if dl.NASPDU != nil {
			if nasBytes, berr := nasPDUBytes(dl); berr == nil {
				resp.NAS, resp.MACVerified = decodeENBDownlinkNAS(ue, nasBytes)
			}
		}
	}

	return resp, nil
}

func handleENBUECapabilityInfo(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	cap := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if req.UERadioCapability != "" {
		b, err := hex.DecodeString(req.UERadioCapability)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "ue_radio_capability must be hex: %v", err)
		}

		cap = b
	}

	mmeID, enbID := forgeIDs(ue, req)

	pdu, err := s1ap.BuildUECapabilityInfoIndication(mmeID, enbID, cap)
	if err != nil {
		return nil, err
	}

	if err := t.Send(pdu, false); err != nil {
		return nil, err
	}

	wctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	resp, _ := t.WaitForMessage(wctx, "ErrorIndication")

	return &SendENBUES1APResponse{S1AP: resp}, nil
}

func handleENBErrorIndication(ctx context.Context, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	encoded, err := s1ap.BuildErrorIndication(sourceMMEID(ue, req), sourceENBID(ue, req), causeRadioNetworkUnspecified)
	if err != nil {
		return nil, err
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	resp := waitDownlinkTolerant(ctx, t, ue, "UEContextReleaseCommand", "ErrorIndication")

	return &SendENBUES1APResponse{S1AP: resp}, nil
}

func handleENBInitialContextSetupFailure(ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	encoded, err := s1ap.BuildInitialContextSetupFailure(sourceMMEID(ue, req), sourceENBID(ue, req), causeRadioNetworkUnspecified)
	if err != nil {
		return nil, err
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	return &SendENBUES1APResponse{}, nil
}

func handleENBTrackingAreaUpdate(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	guti := naseps.GUTIParams{
		MCC: ue.GUTIMCC, MNC: ue.GUTIMNC,
		MMEGroupID: ue.GUTIGroupID, MMECode: ue.GUTICode, MTMSI: ue.GUTIMTMSI,
	}

	tau, err := naseps.BuildTrackingAreaUpdateRequest(naseps.TrackingAreaUpdateRequestParams{
		UpdateType: req.EPSUpdateType,
		ActiveFlag: false,
		KSI:        ue.KSI,
		GUTI:       guti,
	})
	if err != nil {
		return nil, err
	}

	protected, err := encodeENBUplinkNAS(ue, tau, naseps.SHTIntegrityProtectedCiphered, req)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	dl := waitDownlinkTolerant(ctx, t, ue, "DownlinkNASTransport")
	if dl == nil {
		return &SendENBUES1APResponse{}, nil
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	nas, macVerified := decodeENBDownlinkNAS(ue, nasBytes)
	if nas == nil {
		return &SendENBUES1APResponse{S1AP: dl, MACVerified: macVerified}, nil
	}

	if nas.GUTI != nil {
		ue.GUTIMCC = nas.GUTI.MCC
		ue.GUTIMNC = nas.GUTI.MNC
		ue.GUTIGroupID = uint16(nas.GUTI.MMEGroupID)
		ue.GUTICode = uint8(nas.GUTI.MMECode)

		if v, perr := strconv.ParseUint(nas.GUTI.MTMSI, 16, 32); perr == nil {
			ue.GUTIMTMSI = uint32(v)
		}

		complete, berr := naseps.BuildTrackingAreaUpdateComplete()
		if berr != nil {
			return nil, berr
		}

		protectedC, perr := encodeENBUplinkNAS(ue, complete, naseps.SHTIntegrityProtectedCiphered, nil)
		if perr != nil {
			return nil, perr
		}

		if serr := sendUplink(enb, ue, t, protectedC, req); serr != nil {
			return nil, serr
		}
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas, MACVerified: macVerified}, nil
}

func handleENBReleaseRequest(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	mmeID, enbID := forgeIDs(ue, req)

	cause := s1ap.CauseRadioNetworkUserInactivity
	if req.ReleaseCause != nil {
		cause = *req.ReleaseCause
	}

	rr, err := s1ap.BuildUEContextReleaseRequest(mmeID, enbID, cause)
	if err != nil {
		return nil, err
	}

	if err := t.Send(rr, false); err != nil {
		return nil, err
	}

	if req.MMEUES1APIDOverride != nil || req.ENBUES1APIDOverride != nil {
		resp, _ := t.WaitForMessage(ctx, "ErrorIndication", "UEContextReleaseCommand")
		return &SendENBUES1APResponse{S1AP: resp}, nil
	}

	dl, err := waitDownlink(ctx, t, ue, "UEContextReleaseCommand", "ErrorIndication")
	if err != nil {
		return &SendENBUES1APResponse{}, nil
	}

	if dl.MessageType != "UEContextReleaseCommand" {
		return &SendENBUES1APResponse{S1AP: dl}, nil
	}

	comp, err := s1ap.BuildUEContextReleaseComplete(ue.MMEUES1APID, ue.ENBUES1APID)
	if err != nil {
		return nil, err
	}

	if err := t.Send(comp, false); err != nil {
		return nil, err
	}

	return &SendENBUES1APResponse{S1AP: dl}, nil
}

func handleENBServiceRequest(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	count := ue.NextUL()
	if req.NASCountOverride != nil {
		count = *req.NASCountOverride
	}

	sr, err := naseps.BuildServiceRequest(naseps.ServiceRequestParams{
		KSI:     ue.KSI,
		Count:   count,
		KnasInt: ue.KnasInt,
		EIA:     ue.IntegrityAlg,
	})
	if err != nil {
		return nil, err
	}

	if req.CorruptMAC {
		sr[3] ^= 0xff
	}

	mtmsi := ue.GUTIMTMSI
	if req.MTMSIOverride != nil {
		mtmsi = *req.MTMSIOverride
	}

	init, err := s1ap.BuildInitialUEMessage(s1ap.InitialUEMessageParams{
		ENBUES1APID: ue.ENBUES1APID, NASPDU: sr, MCC: enb.MCC, MNC: enb.MNC, TAC: enb.TAC, CellID: 1,
		STMSI: &s1ap.STMSIParams{MMEC: ue.GUTICode, MTMSI: mtmsi},
	})
	if err != nil {
		return nil, err
	}

	if err := t.Send(init, false); err != nil {
		return nil, err
	}

	dl := waitDownlinkTolerant(ctx, t, ue, "InitialContextSetupRequest", "DownlinkNASTransport")
	if dl == nil {
		return &SendENBUES1APResponse{}, nil
	}

	learnMMEID(ue, dl)
	resp := &SendENBUES1APResponse{S1AP: dl}

	switch dl.MessageType {
	case "InitialContextSetupRequest":
		icsResp, ierr := s1ap.BuildInitialContextSetupResponse(s1ap.InitialContextSetupResponseParams{
			MMEUES1APID: ue.MMEUES1APID, ENBUES1APID: ue.ENBUES1APID,
			ERABID: ue.ERABID, ENBN3Addr: enb.N3Addr, GTPTEID: ue.ENBUES1APID,
		})
		if ierr != nil {
			return nil, ierr
		}

		if err := t.Send(icsResp, false); err != nil {
			return nil, err
		}
	case "DownlinkNASTransport":
		if dl.NASPDU != nil {
			if nasBytes, berr := nasPDUBytes(dl); berr == nil {
				resp.NAS, resp.MACVerified = decodeENBDownlinkNAS(ue, nasBytes)
			}
		}
	}

	return resp, nil
}

func handleENBDetach(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "raw_nas_pdu must be hex: %v", err)
		}

		nasPDU = raw
	} else {
		guti := naseps.GUTIParams{
			MCC: ue.GUTIMCC, MNC: ue.GUTIMNC,
			MMEGroupID: ue.GUTIGroupID, MMECode: ue.GUTICode, MTMSI: ue.GUTIMTMSI,
		}

		pdu, err := naseps.BuildDetachRequest(req.SwitchOff, ue.KSI, guti)
		if err != nil {
			return nil, err
		}

		nasPDU, err = encodeENBUplinkNAS(ue, pdu, naseps.SHTIntegrityProtectedCiphered, nil)
		if err != nil {
			return nil, err
		}
	}

	if err := sendUplink(enb, ue, t, nasPDU, req); err != nil {
		return nil, err
	}

	if req.SwitchOff {
		return &SendENBUES1APResponse{S1AP: waitDownlinkTolerant(ctx, t, ue, "UEContextReleaseCommand")}, nil
	}

	dl, err := waitDownlink(ctx, t, ue, "DownlinkNASTransport")
	if err != nil {
		return nil, err
	}

	resp := &SendENBUES1APResponse{S1AP: dl}

	if dl.NASPDU != nil {
		nasBytes, berr := nasPDUBytes(dl)
		if berr != nil {
			return nil, berr
		}

		resp.NAS, resp.MACVerified = decodeENBDownlinkNAS(ue, nasBytes)
	}

	return resp, nil
}

func handleENBInjectNAS(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	var nasPDU []byte

	switch {
	case req.ReplayLast:
		if ue.LastUplinkNAS == nil {
			return nil, httpErrorf(http.StatusBadRequest, "no prior uplink to replay")
		}

		nasPDU = ue.LastUplinkNAS
	case req.RawNASPDU != nil:
		b, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "raw_nas_pdu must be hex: %v", err)
		}

		nasPDU = b
	default:
		return nil, httpErrorf(http.StatusBadRequest, "inject_nas requires raw_nas_pdu or replay_last")
	}

	mmeID := ue.MMEUES1APID
	if req.MMEUES1APIDOverride != nil {
		mmeID = *req.MMEUES1APIDOverride
	}

	enbID := ue.ENBUES1APID
	if req.ENBUES1APIDOverride != nil {
		enbID = *req.ENBUES1APIDOverride
	}

	ul, err := s1ap.BuildUplinkNASTransport(s1ap.UplinkNASTransportParams{
		MMEUES1APID: mmeID, ENBUES1APID: enbID, NASPDU: nasPDU,
		MCC: enb.MCC, MNC: enb.MNC, TAC: enb.TAC, CellID: 1,
	})
	if err != nil {
		return nil, err
	}

	if err := t.Send(ul, false); err != nil {
		return nil, err
	}

	resp, err := t.WaitForMessage(ctx, "DownlinkNASTransport", "ErrorIndication", "UEContextReleaseCommand")
	if err != nil {
		return &SendENBUES1APResponse{}, nil
	}

	return &SendENBUES1APResponse{S1AP: resp}, nil
}
