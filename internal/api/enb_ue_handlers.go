// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

func erabSGWIP(enb *store.ENBContext, e s1ap.ERABSetupItemJSON) string {
	if a, err := netip.ParseAddr(enb.N3Addr); err == nil && a.Is6() {
		return firstNonEmpty(e.TransportLayerAddressIPv6, e.TransportLayerAddress)
	}

	return firstNonEmpty(e.TransportLayerAddress, e.TransportLayerAddressIPv6)
}

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

func (h *Handler) CreateENBUE(w http.ResponseWriter, r *http.Request) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	var req CreateENBUERequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	imsi := strings.TrimPrefix(req.IMSI, "imsi-")
	if imsi == "" {
		writeError(w, http.StatusBadRequest, "imsi is required")
		return
	}

	enbUES1APID := enb.AllocateENBUES1APID()
	ueID := fmt.Sprintf("%d", enbUES1APID)

	ue := store.NewUEEPSContext(ueID, enbUES1APID, &store.CreateUEEPSOpts{
		IMSI:   imsi,
		IMEISV: req.IMEISV,
		K:      req.K,
		OPc:    req.OPc,
		AMF:    req.AMF,
		SQN:    req.SQN,
	})

	if req.UENetworkCapability != "" {
		cap, err := hex.DecodeString(req.UENetworkCapability)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("ue_network_capability must be hex: %v", err))
			return
		}

		ue.UENetworkCapability = cap
	}

	enb.CreateUE(ue)

	writeJSON(w, http.StatusCreated, CreateENBUEResponse{UEID: ue.ID, ENBUES1APID: ue.ENBUES1APID})
}

func (h *Handler) GetENBUE(w http.ResponseWriter, r *http.Request) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	ue, ok := enb.GetUE(r.PathValue("ue_id"))
	if !ok {
		writeError(w, http.StatusNotFound, "ue not found")
		return
	}

	bearers := make([]ENBUEBearer, 0, len(ue.Bearers))
	for _, b := range ue.Bearers {
		bearers = append(bearers, ENBUEBearer{EBI: b.EBI, APN: b.APN, UEIP: b.UEIP})
	}

	writeJSON(w, http.StatusOK, ENBUEStateResponse{
		UEID:           ue.ID,
		IMSI:           ue.IMSI,
		IMEISV:         ue.IMEISV,
		UEIP:           ue.UEIP,
		SecurityActive: ue.SecurityActive,
		MMEUES1APID:    ue.MMEUES1APID,
		ENBUES1APID:    ue.ENBUES1APID,
		DefaultEBI:     ue.EPSBearerID,
		Bearers:        bearers,
	})
}

func (h *Handler) SendENBUES1AP(w http.ResponseWriter, r *http.Request) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	t, ok := h.S1APTransports[enb.ID]
	if !ok {
		writeError(w, http.StatusNotFound, "enb has no S1-MME association")
		return
	}

	ue, ok := enb.GetUE(r.PathValue("ue_id"))
	if !ok {
		writeError(w, http.StatusNotFound, "ue not found")
		return
	}

	var req SendENBUES1APRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	var (
		resp *SendENBUES1APResponse
		herr error
	)

	switch req.MessageType {
	case "attach_request":
		resp, herr = handleENBAttachRequest(ctx, enb, ue, t, &req)
	case "authentication_response":
		resp, herr = handleENBAuthenticationResponse(ctx, enb, ue, t, &req)
	case "authentication_failure":
		resp, herr = handleENBAuthenticationFailure(ctx, enb, ue, t, &req)
	case "identity_response":
		resp, herr = handleENBIdentityResponse(ctx, enb, ue, t, &req)
	case "inject_nas":
		resp, herr = handleENBInjectNAS(ctx, enb, ue, t, &req)
	case "detach_request":
		resp, herr = handleENBDetach(ctx, enb, ue, t, &req)
	case "release_request":
		resp, herr = handleENBReleaseRequest(ctx, enb, ue, t, &req)
	case "service_request":
		resp, herr = handleENBServiceRequest(ctx, enb, ue, t, &req)
	case "tracking_area_update":
		resp, herr = handleENBTrackingAreaUpdate(ctx, enb, ue, t, &req)
	case "ue_capability_info":
		resp, herr = handleENBUeCapabilityInfo(ctx, enb, ue, t, &req)
	case "path_switch":
		resp, herr = handleENBPathSwitch(ctx, enb, ue, t, &req)
	case "handover_required":
		resp, herr = handleENBHandoverRequired(h.Store, ue, t, &req)
	case "handover_cancel":
		resp, herr = handleENBHandoverCancel(ctx, ue, t, &req)
	case "enb_status_transfer":
		resp, herr = handleENBEnbStatusTransfer(ue, t, &req)
	case "error_indication":
		resp, herr = handleENBErrorIndication(ctx, ue, t, &req)
	case "initial_context_setup_failure":
		resp, herr = handleENBInitialContextSetupFailure(ue, t, &req)
	case "modify_response":
		resp, herr = handleENBModifyResponse(ue, t, &req)
	case "pdn_connectivity":
		resp, herr = handleENBPdnConnectivity(ctx, enb, ue, t, &req)
	case "pdn_disconnect":
		resp, herr = handleENBPdnDisconnect(ctx, enb, ue, t, &req)
	case "modify_eps_bearer_context_accept":
		resp, herr = handleENBModifyBearerAccept(enb, ue, t, &req)
	case "deactivate_eps_bearer_context_accept":
		resp, herr = handleENBDeactivateBearerAccept(enb, ue, t, &req)
	case "status_esm":
		resp, herr = handleENBStatusESM(enb, ue, t, &req)
	case "bearer_resource_allocation_request":
		resp, herr = handleENBBearerResourceAllocation(enb, ue, t, &req)
	case "bearer_resource_modification_request":
		resp, herr = handleENBBearerResourceModification(enb, ue, t, &req)
	case "esm_information_response":
		resp, herr = handleENBEsmInformationResponse(enb, ue, t, &req)
	case "security_mode_complete":
		resp, herr = handleENBSecurityModeComplete(ctx, enb, ue, t, &req)
	case "security_mode_reject":
		resp, herr = handleENBSecurityModeReject(ctx, enb, ue, t, &req)
	case "attach_complete":
		resp, herr = handleENBAttachComplete(ctx, enb, ue, t, &req)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported message_type %q", req.MessageType))
		return
	}

	if herr != nil {
		writeError(w, statusForError(herr), herr.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
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

	annotateSecurityHeaderType(nas, plain)

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
			annotateSecurityHeaderType(nas, plain)
		}
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

// epsDLSequenceNumber returns the NAS sequence number of a downlink security-protected
// EPS NAS message (TS 24.301 §9.1: 1-octet header, 4-octet MAC, then the sequence number).
func epsDLSequenceNumber(nasBytes []byte) uint8 {
	const snOffset = 5
	if len(nasBytes) <= snOffset {
		return 0
	}

	return nasBytes[snOffset]
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

	sht, err := naseps.SecurityHeader(nasBytes)
	if err != nil {
		return nil, err
	}

	if sht == naseps.SHTPlain {
		nas, derr := naseps.Decode(nasBytes)
		if derr != nil {
			return nil, derr
		}

		return &SendENBUES1APResponse{S1AP: dl, NAS: annotateSecurityHeaderType(nas, nasBytes)}, nil
	}

	// The Security Mode Command is not ciphered, so the algorithms it selects are readable before their keys exist.
	inner, err := naseps.PeekProtectedPayload(nasBytes)
	if err != nil {
		return nil, err
	}

	smc, err := naseps.Decode(inner)
	if err != nil {
		return nil, err
	}

	if smc.SelectedCipheringAlgorithm == nil || smc.SelectedIntegrityAlgorithm == nil {
		return nil, fmt.Errorf("expected Security Mode Command, got %s", smc.MessageType)
	}

	ue.CipheringAlg = uint8(*smc.SelectedCipheringAlgorithm)
	ue.IntegrityAlg = uint8(*smc.SelectedIntegrityAlgorithm)

	if ue.KnasEnc, ue.KnasInt, err = crypto.DeriveEPSNASKeys(ue.Kasme, ue.CipheringAlg, ue.IntegrityAlg); err != nil {
		return nil, err
	}

	ue.SecurityActive = true
	ue.ULCount = 0
	ue.DLCount = 0

	_, verr := naseps.Unprotect(nasBytes, ue.NextDL(epsDLSequenceNumber(nasBytes)), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	verified := verr == nil

	return &SendENBUES1APResponse{S1AP: dl, NAS: annotateSecurityHeaderType(smc, nasBytes), MACVerified: &verified}, nil
}

func handleENBIdentityResponse(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	pdu, err := naseps.BuildIdentityResponse(ue.IMSI)
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

	plain, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateSecurityHeaderType(nas, plain)

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

	dl, err := waitDownlink(ctx, t, ue, "DownlinkNASTransport")
	if err != nil {
		return nil, err
	}

	plain, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateSecurityHeaderType(nas, plain)

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

	protected, err := naseps.Protect(smc, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if req.CorruptMAC {
		// protected[1] is the first octet of the NAS-MAC (header‖MAC‖seq‖payload).
		protected[1] ^= 0xff
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	if req.CorruptMAC {
		return &SendENBUES1APResponse{S1AP: waitDownlinkTolerant(ctx, t, ue, "InitialContextSetupRequest")}, nil
	}

	dl, err := waitDownlink(ctx, t, ue, "InitialContextSetupRequest")
	if err != nil {
		return nil, err
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(epsDLSequenceNumber(nasBytes)), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, fmt.Errorf("unprotect attach accept: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateSecurityHeaderType(nas, nasBytes)

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

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

func ueIPFromPDNAddress(pdnHex string) string {
	b, err := hex.DecodeString(pdnHex)
	if err != nil || len(b) < 5 || b[0] != naseps.PDNTypeIPv4 {
		return ""
	}

	return net.IP(b[1:5]).String()
}

// TS 24.301 §9.9.3.9.
const emmCauseSecurityCapMismatch uint8 = 23

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

	dl, err := waitDownlink(ctx, t, ue, "UEContextReleaseCommand")
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

	protected, err := naseps.Protect(ac, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
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

	if dl := waitDownlinkTolerant(wctx, t, ue, "DownlinkNASTransport"); dl != nil && dl.NASPDU != nil {
		if nasBytes, berr := nasPDUBytes(dl); berr == nil {
			if plain, perr := naseps.Unprotect(nasBytes, ue.NextDL(epsDLSequenceNumber(nasBytes)), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt); perr == nil {
				resp.S1AP = dl
				resp.NAS, _ = naseps.Decode(plain)
				resp.NAS = annotateSecurityHeaderType(resp.NAS, nasBytes)
			}
		}
	}

	return resp, nil
}

func sendUplink(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, nasPDU []byte, req *SendENBUES1APRequest) error {
	mmeID, enbID := forgeIDs(ue, req)

	ul, err := s1ap.BuildUplinkNASTransport(s1ap.UplinkNASTransportParams{
		MMEUES1APID: mmeID, ENBUES1APID: enbID, NASPDU: nasPDU,
		MCC: enb.MCC, MNC: enb.MNC, TAC: enb.TAC, CellID: 1,
	})
	if err != nil {
		return err
	}

	ue.LastUplinkNAS = nasPDU

	return t.Send(ul, false)
}

func handleENBUeCapabilityInfo(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
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

func forgeIDs(ue *store.UEEPSContext, req *SendENBUES1APRequest) (uint32, uint32) {
	mmeID, enbID := ue.MMEUES1APID, ue.ENBUES1APID
	if req == nil {
		return mmeID, enbID
	}

	if req.MMEUES1APIDOverride != nil {
		mmeID = *req.MMEUES1APIDOverride
	}

	if req.ENBUES1APIDOverride != nil {
		enbID = *req.ENBUES1APIDOverride
	}

	return mmeID, enbID
}

func handleENBPathSwitch(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, fmt.Errorf("no UE context; complete an attach first")
	}

	sourceMME := ue.MMEUES1APID
	if req.MMEUES1APIDOverride != nil {
		sourceMME = *req.MMEUES1APIDOverride
	}

	erabID := ue.ERABID
	if req.PathSwitchERABID != nil {
		erabID = *req.PathSwitchERABID
	}

	// The S1AP encoding drops the EEA0/EIA0 bit, so shift the octets left.
	netcap := ue.UENetworkCapability
	if len(netcap) < 2 {
		netcap = naseps.DefaultUENetworkCapability
	}

	encAlg := uint16(netcap[0]<<1) << 8
	intAlg := uint16(netcap[1]<<1) << 8

	if req.PathSwitchEEA != nil {
		encAlg = *req.PathSwitchEEA
	}

	if req.PathSwitchEIA != nil {
		intAlg = *req.PathSwitchEIA
	}

	psr, err := s1ap.BuildPathSwitchRequest(s1ap.PathSwitchRequestParams{
		ENBUES1APID:                   ue.ENBUES1APID,
		SourceMMEUES1APID:             sourceMME,
		ERABID:                        erabID,
		TargetS1UAddr:                 enb.N3Addr,
		TargetTEID:                    ue.ENBUES1APID + 0x1000,
		MCC:                           enb.MCC,
		MNC:                           enb.MNC,
		TAC:                           enb.TAC,
		CellID:                        1,
		EncryptionAlgorithms:          encAlg,
		IntegrityProtectionAlgorithms: intAlg,
		Duplicate:                     req.DuplicateERAB,
	})
	if err != nil {
		return nil, err
	}

	if err := t.Send(psr, false); err != nil {
		return nil, err
	}

	dl := waitDownlinkTolerant(ctx, t, ue, "PathSwitchRequestAcknowledge", "PathSwitchRequestFailure")
	if dl == nil {
		return &SendENBUES1APResponse{}, nil
	}

	return &SendENBUES1APResponse{S1AP: dl}, nil
}

func handleENBPdnConnectivity(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	pti := uint8(5)
	if req.PTI != nil {
		pti = *req.PTI
	}

	pdnType := req.PDNType
	if pdnType == 0 {
		pdnType = naseps.PDNTypeIPv4
	}

	params := naseps.PDNConnectivityParams{PTI: pti, PDNType: pdnType, APN: req.APN}
	if req.RequestEBI != nil {
		params.EPSBearerIdentity = *req.RequestEBI
	}

	esm, err := naseps.BuildPDNConnectivityRequestWith(params)
	if err != nil {
		return nil, err
	}

	protected, err := naseps.Protect(esm, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	dl := waitDownlinkTolerant(ctx, t, ue, "ERABSetupRequest", "DownlinkNASTransport")
	if dl == nil {
		return &SendENBUES1APResponse{}, nil
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(epsDLSequenceNumber(nasBytes)), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, fmt.Errorf("unprotect pdn connectivity reply: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateSecurityHeaderType(nas, nasBytes)

	if dl.MessageType != "ERABSetupRequest" || nas.MessageType != "activate_default_eps_bearer_context_request" {
		return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
	}

	// Withholding the accept leaves timer T3485 running so its retransmission is observable (TS 24.301 §6.4.1.6 a).
	if req.WithholdAccept {
		return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
	}

	if err := acceptAdditionalBearer(enb, ue, t, dl, nas, req); err != nil {
		return nil, err
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

func acceptAdditionalBearer(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, dl *s1ap.S1APResponse, nas *naseps.NASResponse, req *SendENBUES1APRequest) error {
	if nas.EPSBearerIdentity == nil {
		return fmt.Errorf("activate default without an EPS bearer identity")
	}

	ebi := uint8(*nas.EPSBearerIdentity)
	pti := uint8(0)
	if nas.BearerPTI != nil {
		pti = uint8(*nas.BearerPTI)
	}

	bearer := &store.EPSBearer{
		EBI:    ebi,
		PTI:    pti,
		APN:    nas.APN,
		UEIP:   ueIPFromPDNAddress(nas.PDNAddress),
		DLTeid: (ue.ENBUES1APID << 8) | uint32(ebi),
	}

	if len(dl.ERABSetupItems) > 0 {
		e := dl.ERABSetupItems[0]
		bearer.ULTeid = e.GTPTEID
		bearer.SGWIP = erabSGWIP(enb, e)
	}

	ue.Bearers[ebi] = bearer

	erabResp, err := s1ap.BuildERABSetupResponse(s1ap.InitialContextSetupResponseParams{
		MMEUES1APID: ue.MMEUES1APID, ENBUES1APID: ue.ENBUES1APID,
		ERABID: ebi, ENBN3Addr: enb.N3Addr, GTPTEID: bearer.DLTeid,
	})
	if err != nil {
		return err
	}

	if err := t.Send(erabResp, false); err != nil {
		return err
	}

	accept, err := naseps.BuildActivateDefaultEPSBearerContextAccept(ebi, pti)
	if err != nil {
		return err
	}

	protectedAccept, err := naseps.Protect(accept, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return err
	}

	return sendUplink(enb, ue, t, protectedAccept, req)
}

func handleENBPdnDisconnect(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	pti := uint8(6)
	if req.PTI != nil {
		pti = *req.PTI
	}

	linkedEBI := ue.EPSBearerID
	if req.LinkedEBI != nil {
		linkedEBI = *req.LinkedEBI
	}

	esm, err := naseps.BuildPDNDisconnectRequest(pti, linkedEBI)
	if err != nil {
		return nil, err
	}

	protected, err := naseps.Protect(esm, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	dl := waitDownlinkTolerant(ctx, t, ue, "ERABReleaseCommand", "DownlinkNASTransport")
	if dl == nil {
		return &SendENBUES1APResponse{}, nil
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(epsDLSequenceNumber(nasBytes)), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, fmt.Errorf("unprotect pdn disconnect reply: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateSecurityHeaderType(nas, nasBytes)

	// Withholding the accept leaves timer T3495 running so its retransmission is observable (TS 24.301 §6.4.4.5 a).
	if req.WithholdAccept {
		return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
	}

	if nas.MessageType == "deactivate_eps_bearer_context_request" && nas.EPSBearerIdentity != nil {
		deactEBI := uint8(*nas.EPSBearerIdentity)
		deactPTI := uint8(0)
		if nas.BearerPTI != nil {
			deactPTI = uint8(*nas.BearerPTI)
		}

		// The radio-bearer release must be confirmed before the NAS accept.
		if dl.MessageType == "ERABReleaseCommand" {
			relResp, rerr := s1ap.BuildERABReleaseResponse(ue.MMEUES1APID, ue.ENBUES1APID, deactEBI)
			if rerr != nil {
				return nil, rerr
			}

			if serr := t.Send(relResp, false); serr != nil {
				return nil, serr
			}
		}

		accept, berr := naseps.BuildDeactivateEPSBearerContextAccept(deactEBI, deactPTI)
		if berr != nil {
			return nil, berr
		}

		protectedAccept, perr := naseps.Protect(accept, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
		if perr != nil {
			return nil, perr
		}

		if serr := sendUplink(enb, ue, t, protectedAccept, req); serr != nil {
			return nil, serr
		}

		delete(ue.Bearers, deactEBI)
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

// TS 24.301 §9.9.4.4.
const esmCauseProtocolErrorUnspec uint8 = 111

func handleENBStatusESM(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	cause := esmCauseProtocolErrorUnspec
	if req.ESMCause != nil {
		cause = *req.ESMCause
	}

	esm, err := naseps.BuildESMStatus(esmBearerID(ue, req), esmPTI(req), cause)
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBBearerResourceAllocation(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildBearerResourceAllocationRequest(esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBBearerResourceModification(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildBearerResourceModificationRequest(esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBEsmInformationResponse(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildESMInformationResponse(esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBModifyBearerAccept(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildModifyEPSBearerContextAccept(esmBearerID(ue, req), esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBDeactivateBearerAccept(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildDeactivateEPSBearerContextAccept(esmBearerID(ue, req), esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func sendESM(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, esm []byte, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	protected, err := naseps.Protect(esm, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	return &SendENBUES1APResponse{}, nil
}

func esmBearerID(ue *store.UEEPSContext, req *SendENBUES1APRequest) uint8 {
	if req.EPSBearerIdentity != nil {
		return *req.EPSBearerIdentity
	}

	return ue.EPSBearerID
}

func esmPTI(req *SendENBUES1APRequest) uint8 {
	if req.PTI != nil {
		return *req.PTI
	}

	return 0
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

func handleENBModifyResponse(ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	encoded, err := s1ap.BuildERABModifyResponse(ue.MMEUES1APID, ue.ENBUES1APID, []uint8{esmBearerID(ue, req)})
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

	count := ue.NextUL()
	if req.NASCountOverride != nil {
		count = *req.NASCountOverride
	}

	protected, err := naseps.Protect(tau, naseps.SHTIntegrityProtectedCiphered, count, ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if req.CorruptMAC {
		protected[1] ^= 0xff
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

	sht, err := naseps.SecurityHeader(nasBytes)
	if err != nil {
		return nil, err
	}

	if sht == naseps.SHTPlain {
		nas, derr := naseps.Decode(nasBytes)
		return &SendENBUES1APResponse{S1AP: dl, NAS: annotateSecurityHeaderType(nas, nasBytes)}, derr
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(epsDLSequenceNumber(nasBytes)), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, fmt.Errorf("unprotect TAU accept: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateSecurityHeaderType(nas, nasBytes)

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

		protectedC, perr := naseps.Protect(complete, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
		if perr != nil {
			return nil, perr
		}

		if serr := sendUplink(enb, ue, t, protectedC, req); serr != nil {
			return nil, serr
		}
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
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
			if plain, berr := nasPDUBytes(dl); berr == nil {
				resp.NAS, _ = naseps.Decode(plain)
				resp.NAS = annotateSecurityHeaderType(resp.NAS, plain)
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

		nasPDU, err = naseps.Protect(pdu, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
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

		plain, perr := naseps.Unprotect(nasBytes, ue.NextDL(epsDLSequenceNumber(nasBytes)), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
		if perr != nil {
			return nil, fmt.Errorf("unprotect detach accept: %w", perr)
		}

		if resp.NAS, err = naseps.Decode(plain); err != nil {
			return nil, err
		}

		resp.NAS = annotateSecurityHeaderType(resp.NAS, nasBytes)
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

func waitDownlinkTolerant(ctx context.Context, t *transport.S1APTransport, ue *store.UEEPSContext, types ...string) *s1ap.S1APResponse {
	resp, err := waitDownlink(ctx, t, ue, types...)
	if err != nil {
		return nil
	}

	return resp
}

func waitDownlink(ctx context.Context, t *transport.S1APTransport, ue *store.UEEPSContext, types ...string) (*s1ap.S1APResponse, error) {
	match := func(r *s1ap.S1APResponse) bool {
		return r.ENBUES1APID != nil && *r.ENBUES1APID == int64(ue.ENBUES1APID)
	}

	return t.WaitForMessageMatching(ctx, match, types...)
}

func learnMMEID(ue *store.UEEPSContext, resp *s1ap.S1APResponse) {
	if resp.MMEUES1APID != nil {
		ue.MMEUES1APID = uint32(*resp.MMEUES1APID)
	}
}

func nasPDUBytes(resp *s1ap.S1APResponse) ([]byte, error) {
	if resp.NASPDU == nil {
		return nil, fmt.Errorf("downlink %s carries no NAS PDU", resp.MessageType)
	}

	return hex.DecodeString(*resp.NASPDU)
}

func annotateSecurityHeaderType(nas *naseps.NASResponse, downlink []byte) *naseps.NASResponse {
	if nas == nil {
		return nil
	}

	if sht, err := naseps.SecurityHeader(downlink); err == nil {
		nas.SecurityHeaderType = naseps.SecurityHeaderTypeString(sht)
	}

	return nas
}
