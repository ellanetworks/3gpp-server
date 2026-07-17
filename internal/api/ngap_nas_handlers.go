// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	nasCodec "github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap/ngapType"
)

func registrationOverrides(req *SendNGAPRequest) *nasCodec.RegistrationRequestOverrides {
	return &nasCodec.RegistrationRequestOverrides{
		NgKSI:                        req.NgKSI,
		MobileIdentityOverride:       req.MobileIdentityOverride,
		UESecurityCapabilityOverride: req.UESecurityCapabilityOverride,
		FollowOnRequest:              req.FollowOnRequest,
		NonCurrentNativeNASKSI:       req.NonCurrentNativeNASKSI,
		Capability5GMM:               req.Capability5GMM,
		RequestedNSSAI:               req.RequestedNSSAI,
		LastVisitedRegisteredTAI:     req.LastVisitedRegisteredTAI,
		S1UENetworkCapability:        req.S1UENetworkCapability,
		UplinkDataStatus:             req.UplinkDataStatus,
		PDUSessionStatus:             req.PDUSessionStatus,
		MICOIndication:               req.MICOIndication,
		UEStatus:                     req.UEStatus,
		AdditionalGUTI:               req.AdditionalGUTI,
		AllowedPDUSessionStatus:      req.AllowedPDUSessionStatus,
		UEsUsageSetting:              req.UEsUsageSetting,
		RequestedDRXParameters:       req.RequestedDRXParameters,
		EPSNASMessageContainer:       req.EPSNASMessageContainer,
		LADNIndication:               req.LADNIndication,
		PayloadContainer:             req.PayloadContainer,
		NetworkSlicingIndication:     req.NetworkSlicingIndication,
		UpdateType5GS:                req.UpdateType5GS,
		NASMessageContainer:          req.NASMessageContainer,
		EPSBearerContextStatus:       req.EPSBearerContextStatus,
	}
}

func uplinkOverrides(req *SendNGAPRequest) *ngap.UplinkNASTransportOverrides {
	if req.AmfUeNgapIDOverride == nil && req.RanUeNgapIDOverride == nil {
		return nil
	}

	return &ngap.UplinkNASTransportOverrides{
		AmfUeNgapID: req.AmfUeNgapIDOverride,
		RanUeNgapID: req.RanUeNgapIDOverride,
	}
}

func initialUEOverrides(req *SendNGAPRequest) *ngap.InitialUEMessageOverrides {
	if req.RRCEstablishmentCauseOverride == nil && req.UEContextRequestOverride == nil && req.RanUeNgapIDOverride == nil {
		return nil
	}

	return &ngap.InitialUEMessageOverrides{
		RRCEstablishmentCause: req.RRCEstablishmentCauseOverride,
		UEContextRequest:      req.UEContextRequestOverride,
		RanUeNgapID:           req.RanUeNgapIDOverride,
	}
}

func handleGnBRegistrationRequest(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	if req.RawNASPDU != nil {
		nasPDU, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		if req.ExistingConnection {
			return sendUplinkAndWait(ctx, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
		}

		ngapMsg, err := ngap.BuildInitialUEMessageFromState(ngap.InitialUEMessageFromStateParams{
			RanUeNgapID: ue.RanUeNgapID,
			NASPDU:      nasPDU,
			MCC:         gnb.MCC,
			MNC:         gnb.MNC,
			TAC:         gnb.TAC,
			GnbID:       gnb.GNBID,
			Overrides:   initialUEOverrides(req),
		})
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "build initial ue message: %v", err)
		}

		return sendAndWait(ctx, ue, t, req, ngapMsg, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")
	}

	regType := uint8(nasCodec.RegistrationTypeInitial)
	if req.RegistrationType != nil {
		regType = *req.RegistrationType
	}

	// A mobility or periodic update reuses its security context (TS 24.501 §5.5.1.3).
	mobilityOrPeriodic := regType == nasCodec.RegistrationTypeMobility || regType == nasCodec.RegistrationTypePeriodic
	secured := mobilityOrPeriodic && len(ue.Kamf) > 0

	ngKsi := ksiNoKey
	if secured {
		ngKsi = ue.NgKsi
	}

	nasPDU, err := nasCodec.BuildRegistrationRequest(&nasCodec.RegistrationRequestOpts{
		RegistrationType: regType,
		Suci:             ue.Suci,
		Guti:             ue.Guti,
		SecurityCap:      ue.UeSecurityCapability,
		NgKsi:            ngKsi,
		Overrides:        registrationOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build NAS RegistrationRequest: %v", err)
	}

	if secured {
		nasPDU, err = encodeGNBUplinkNAS(ue, nasPDU, gonas.SecurityHeaderTypeIntegrityProtected, req)
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
		}
	}

	if req.ExistingConnection {
		return sendUplinkAndWait(ctx, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
	}

	ngapMsg, err := ngap.BuildInitialUEMessageFromState(ngap.InitialUEMessageFromStateParams{
		RanUeNgapID: ue.RanUeNgapID,
		NASPDU:      nasPDU,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GnbID:       gnb.GNBID,
		Overrides:   initialUEOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "build initial ue message: %v", err)
	}

	return sendAndWait(ctx, ue, t, req, ngapMsg, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")
}

func handleGnBAuthenticationResponse(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		nasPDU = raw
	} else {
		var resStar []byte

		if req.ResStarOverride != nil {
			var err error

			resStar, err = hex.DecodeString(*req.ResStarOverride)
			if err != nil {
				return nil, httpErrorf(http.StatusBadRequest, "decode res_star_override: %v", err)
			}
		} else if len(ue.LastRAND) == 0 || len(ue.LastAUTN) == 0 {
			resStar = make([]byte, 16)
		} else {
			akaResult, err := crypto.Compute5GAKA(ue.K, ue.OPc, ue.Sqn, ue.Supi, ue.Snn, ue.LastRAND, ue.LastAUTN)
			if err != nil {
				return nil, httpErrorf(http.StatusInternalServerError, "5G-AKA: %v", err)
			}

			ue.Kamf = akaResult.Kamf
			resStar = akaResult.RESStar
		}

		var err error

		nasPDU, err = nasCodec.BuildAuthenticationResponse(resStar)
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build AuthenticationResponse: %v", err)
		}
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
}

func handleGnBSecurityModeComplete(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		nasPDU = raw
	} else {
		innerRegType := uint8(nasCodec.RegistrationTypeInitial)
		if req.RegistrationType != nil {
			innerRegType = *req.RegistrationType
		}

		regReqPDU, err := nasCodec.BuildRegistrationRequest(&nasCodec.RegistrationRequestOpts{
			RegistrationType: innerRegType,
			Suci:             ue.Suci,
			Guti:             ue.Guti,
			SecurityCap:      ue.UeSecurityCapability,
			NgKsi:            ue.NgKsi,
			Overrides:        registrationOverrides(req),
		})
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build inner RegistrationRequest: %v", err)
		}

		smcPDU, err := nasCodec.BuildSecurityModeComplete(regReqPDU, ue.IMEISV)
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build SecurityModeComplete: %v", err)
		}

		nasPDU, err = encodeGNBUplinkNAS(ue, smcPDU,
			gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, req)
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
		}
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, nasPDU, "InitialContextSetupRequest", "DownlinkNASTransport", "ErrorIndication")
}

func handleGnBRegistrationComplete(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	icsResp, err := ngap.BuildInitialContextSetupResponse(ue.AmfUeNgapID, ue.RanUeNgapID)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build InitialContextSetupResponse: %v", err)
	}

	if err := t.Send(icsResp, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send InitialContextSetupResponse: %v", err)
	}

	var nasPDU []byte

	if req.RawNASPDU != nil {
		nasPDU, err = hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}
	} else {
		regCompletePDU, err := nasCodec.BuildRegistrationComplete()
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build RegistrationComplete: %v", err)
		}

		nasPDU, err = encodeGNBUplinkNAS(ue, regCompletePDU,
			gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
		}
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication", "UEContextReleaseCommand")
}

func handleGnBDeregistrationRequest(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		nasPDU = raw
	} else {
		switchOff := uint8(1)
		if req.DeregSwitchOff != nil {
			switchOff = *req.DeregSwitchOff
		}

		deregPDU, err := nasCodec.BuildDeregistrationRequest(&nasCodec.DeregistrationRequestOpts{
			Guti:      ue.Guti,
			Suci:      &ue.Suci,
			NgKsi:     ue.NgKsi,
			SwitchOff: switchOff,
		})
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build DeregistrationRequest: %v", err)
		}

		nasPDU, err = encodeGNBUplinkNAS(ue, deregPDU,
			gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
		}
	}

	encoded, err := ngap.BuildUplinkNASTransport(ngap.UplinkNASTransportParams{
		AmfUeNgapID: ue.AmfUeNgapID,
		RanUeNgapID: ue.RanUeNgapID,
		NASPDU:      nasPDU,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GnbID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"UEContextReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for response: %v", err)
	}

	var nasResp *nasCodec.NASResponse

	var macVerified *bool

	for _, ie := range ngapResp.IEs {
		if ie.NasPDU != nil {
			nasPDUBytes, err := hex.DecodeString(*ie.NasPDU)
			if err != nil {
				continue
			}

			nasResp, macVerified = decodeGNBDownlinkNAS(ue, nasPDUBytes)
		}
	}

	if ngapResp.MessageType == "UEContextReleaseCommand" {
		releaseComplete, err := ngap.BuildUEContextReleaseComplete(ue.AmfUeNgapID, ue.RanUeNgapID)
		if err == nil {
			_ = t.Send(releaseComplete, false)
		}
	}

	return &SendNGAPResponse{
		NGAP:        ngapResp,
		NAS:         nasResp,
		MACVerified: macVerified,
	}, nil
}

func handleGnBUEContextReleaseRequest(ctx context.Context, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	cause := int64(20)
	if req.ReleaseCause != nil {
		cause = *req.ReleaseCause
	}

	amfUeNgapID := ue.AmfUeNgapID
	if req.AmfUeNgapIDOverride != nil {
		amfUeNgapID = *req.AmfUeNgapIDOverride
	}

	ranUeNgapID := ue.RanUeNgapID
	if req.RanUeNgapIDOverride != nil {
		ranUeNgapID = *req.RanUeNgapIDOverride
	}

	encoded, err := ngap.BuildUEContextReleaseRequest(amfUeNgapID, ranUeNgapID, cause)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build UEContextReleaseRequest: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"UEContextReleaseCommand", "ErrorIndication")
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for response: %v", err)
	}

	if ngapResp.MessageType == "UEContextReleaseCommand" {
		releaseComplete, err := ngap.BuildUEContextReleaseComplete(ue.AmfUeNgapID, ue.RanUeNgapID)
		if err == nil {
			_ = t.Send(releaseComplete, false)
		}
	}

	return &SendNGAPResponse{NGAP: ngapResp}, nil
}

func handleGnBIdentityResponse(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		nasPDU = raw
	} else {
		mobileIdentity := ue.Suci.Buffer
		if req.MobileIdentityOverride != nil {
			b, err := hex.DecodeString(*req.MobileIdentityOverride)
			if err != nil {
				return nil, httpErrorf(http.StatusBadRequest, "decode mobile_identity_override: %v", err)
			}

			mobileIdentity = b
		}

		idPDU, err := nasCodec.BuildIdentityResponse(mobileIdentity)
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build IdentityResponse: %v", err)
		}

		nasPDU = idPDU

		if len(ue.Kamf) > 0 {
			nasPDU, err = encodeGNBUplinkNAS(ue, idPDU, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
			if err != nil {
				return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
			}
		}
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")
}

func handleGnBAuthenticationFailure(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		nasPDU = raw
	} else {
		cause := uint8(nasMessage.Cause5GMMMACFailure)
		if req.Cause5GMM != nil {
			cause = *req.Cause5GMM
		}

		var auts []byte

		if cause == nasMessage.Cause5GMMSynchFailure {
			a, err := crypto.ComputeAUTS(ue.K, ue.OPc, ue.Sqn, ue.LastRAND)
			if err != nil {
				return nil, httpErrorf(http.StatusInternalServerError, "compute AUTS: %v", err)
			}

			auts = a
		}

		pdu, err := nasCodec.BuildAuthenticationFailure(cause, auts)
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build AuthenticationFailure: %v", err)
		}

		nasPDU = pdu
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
}

func handleGnBSecurityModeReject(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		nasPDU = raw
	} else {
		cause := uint8(nasMessage.Cause5GMMUESecurityCapabilitiesMismatch)
		if req.Cause5GMM != nil {
			cause = *req.Cause5GMM
		}

		pdu, err := nasCodec.BuildSecurityModeReject(cause)
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build SecurityModeReject: %v", err)
		}

		nasPDU = pdu
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, nasPDU, "UEContextReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
}

// NGAP BitString left-aligns the 10-bit Set ID and 6-bit Pointer into their octets.
func fiveGSTMSIFromGUTI(guti *nasType.GUTI5G) *ngap.FiveGSTMSIFromGUTI {
	if guti == nil {
		return nil
	}

	setID := guti.GetAMFSetID()
	pointer := guti.GetAMFPointer()
	tmsi := guti.GetTMSI5G()

	setIDBytes := []byte{byte(setID >> 2), byte((setID & 0x3) << 6)}
	pointerByte := []byte{pointer << 2}

	return &ngap.FiveGSTMSIFromGUTI{
		AMFSetID:   hex.EncodeToString(setIDBytes),
		AMFPointer: hex.EncodeToString(pointerByte),
		FiveGTMSI:  hex.EncodeToString(tmsi[:]),
	}
}

func serviceRequestPDUStatus(ue *store.UEContext, req *SendNGAPRequest) (*[16]bool, error) {
	if req.PDUSessionStatus != nil {
		raw, err := hex.DecodeString(*req.PDUSessionStatus)
		if err != nil {
			return nil, err
		}

		var buf [2]byte
		copy(buf[:], raw)
		flags := uint16(buf[0]) | uint16(buf[1])<<8

		var status [16]bool
		for i := range status {
			status[i] = flags&(1<<uint(i)) != 0
		}

		return &status, nil
	}

	var status [16]bool
	if ue.PDUSessionID >= 1 && ue.PDUSessionID <= 15 {
		status[ue.PDUSessionID] = true
	}

	return &status, nil
}

func handleGnBServiceRequest(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	ue.RanUeNgapID = gnb.AllocateRanUeNgapID()

	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		nasPDU = raw
	} else {
		serviceType := nasMessage.ServiceTypeData
		if req.ServiceType != nil {
			serviceType = *req.ServiceType
		}

		status, err := serviceRequestPDUStatus(ue, req)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode pdu_session_status: %v", err)
		}

		srPDU, err := nasCodec.BuildServiceRequest(&nasCodec.ServiceRequestOpts{
			ServiceType:      serviceType,
			NgKsi:            ue.NgKsi,
			Guti:             ue.Guti,
			PDUSessionStatus: status,
		})
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build ServiceRequest: %v", err)
		}

		if len(ue.Kamf) > 0 {
			nasPDU, err = encodeGNBUplinkNAS(ue, srPDU, gonas.SecurityHeaderTypeIntegrityProtected, req)
			if err != nil {
				return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
			}
		} else {
			nasPDU = srPDU
		}
	}

	overrides := initialUEOverrides(req)
	if overrides == nil || overrides.RRCEstablishmentCause == nil {
		moData := int64(ngapType.RRCEstablishmentCausePresentMoData)
		if overrides == nil {
			overrides = &ngap.InitialUEMessageOverrides{}
		}
		overrides.RRCEstablishmentCause = &moData
	}

	ngapMsg, err := ngap.BuildInitialUEMessageFromState(ngap.InitialUEMessageFromStateParams{
		RanUeNgapID: ue.RanUeNgapID,
		NASPDU:      nasPDU,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GnbID:       gnb.GNBID,
		GUTI:        fiveGSTMSIFromGUTI(ue.Guti),
		Overrides:   overrides,
	})
	if err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "build initial ue message: %v", err)
	}

	encoded, err := ngap.Encode(ngapMsg)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"InitialContextSetupRequest", "DownlinkNASTransport", "PDUSessionResourceSetupRequest", "ErrorIndication")
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for service request response: %v", err)
	}

	var nasResp *nasCodec.NASResponse

	var macVerified *bool

	for _, ie := range ngapResp.IEs {
		// An Error Indication echoes the AP IDs it was sent; it assigns none.
		if ie.AmfUeNgapID != nil && ngapResp.MessageType != "ErrorIndication" {
			ue.AmfUeNgapID = *ie.AmfUeNgapID
		}

		if ie.NasPDU != nil {
			nasPDUBytes, derr := hex.DecodeString(*ie.NasPDU)
			if derr != nil {
				continue
			}

			nasResp, macVerified = decodeGNBDownlinkNAS(ue, nasPDUBytes)
		}
	}

	if ngapResp.MessageType == "InitialContextSetupRequest" {
		icsResp, berr := ngap.BuildInitialContextSetupResponse(ue.AmfUeNgapID, ue.RanUeNgapID)
		if berr == nil {
			_ = t.Send(icsResp, false)
		}
	}

	return &SendNGAPResponse{
		NGAP:        ngapResp,
		NAS:         nasResp,
		MACVerified: macVerified,
	}, nil
}

func handleGnBInjectNAS(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	var nasPDU []byte

	switch {
	case req.ReplayLast:
		if len(ue.LastUplinkNAS) == 0 {
			return nil, httpErrorf(http.StatusBadRequest, "no prior uplink to replay")
		}

		nasPDU = ue.LastUplinkNAS
	case req.RawNASPDU != nil:
		decoded, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "raw_nas_pdu must be hex: %v", err)
		}

		nasPDU = decoded
	default:
		return nil, httpErrorf(http.StatusBadRequest, "inject_nas requires raw_nas_pdu or replay_last")
	}

	encoded, err := ngap.BuildUplinkNASTransport(ngap.UplinkNASTransportParams{
		AmfUeNgapID: ue.AmfUeNgapID,
		RanUeNgapID: ue.RanUeNgapID,
		NASPDU:      nasPDU,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GnbID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build UplinkNASTransport: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	ngapResp, err := t.WaitForMessage(ctx, "DownlinkNASTransport", "ErrorIndication", "UEContextReleaseCommand")
	if err != nil {
		return &SendNGAPResponse{}, nil
	}

	return &SendNGAPResponse{NGAP: ngapResp}, nil
}

func handleGnBUECapabilityInfo(ctx context.Context, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	radioCap := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	if req.UERadioCapability != nil {
		decoded, err := hex.DecodeString(*req.UERadioCapability)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "ue_radio_capability must be hex: %v", err)
		}

		radioCap = decoded
	}

	encoded, err := ngap.BuildUERadioCapabilityInfoIndication(effectiveAmfID(req, ue), effectiveRanID(req, ue), radioCap)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build UERadioCapabilityInfoIndication: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)), "ErrorIndication")
	if err != nil {
		return &SendNGAPResponse{}, nil
	}

	return &SendNGAPResponse{NGAP: ngapResp}, nil
}

func handleGnBInitialContextSetupFailure(ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	encoded, err := ngap.BuildInitialContextSetupFailure(effectiveAmfID(req, ue), effectiveRanID(req, ue), causeRadioNetworkUnspecified)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build InitialContextSetupFailure: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendNGAPResponse{}, nil
}

func handleGnBErrorIndication(ctx context.Context, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	encoded, err := ngap.BuildErrorIndication(effectiveAmfID(req, ue), effectiveRanID(req, ue), causeRadioNetworkUnspecified)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build ErrorIndication: %v", err)
	}

	return sendRawAndWait(ctx, ue, t, req, encoded, "UEContextReleaseCommand", "ErrorIndication")
}
