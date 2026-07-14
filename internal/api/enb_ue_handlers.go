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
	"strconv"
	"strings"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

// ksiNoKey is the NAS key set identifier value "no key available" (TS 24.301
// §9.9.3.21), used in the initial Attach Request.
const ksiNoKey uint8 = 7

// EMM causes for an Authentication Failure (TS 24.301 §9.9.3.9, §5.4.2.6).
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

	ue := enb.CreateUE(imsi, req.K, req.OPc, req.AMF, req.SQN)

	if req.UENetworkCapability != "" {
		cap, err := hex.DecodeString(req.UENetworkCapability)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("ue_network_capability must be hex: %v", err))
			return
		}

		ue.UENetworkCapability = cap
	}

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

	bearers := make([]map[string]any, 0, len(ue.Bearers))
	for _, b := range ue.Bearers {
		bearers = append(bearers, map[string]any{
			"ebi": b.EBI, "apn": b.APN, "ue_ip": b.UEIP,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ue_id":           ue.ID,
		"imsi":            ue.IMSI,
		"ue_ip":           ue.UEIP,
		"security_active": ue.SecurityActive,
		"mme_ue_s1ap_id":  ue.MMEUES1APID,
		"enb_ue_s1ap_id":  ue.ENBUES1APID,
		"default_ebi":     ue.EPSBearerID,
		"bearers":         bearers,
	})
}

func (h *Handler) SendENBNAS(w http.ResponseWriter, r *http.Request) {
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

	var req SendENBNASRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	var (
		resp *SendENBNASResponse
		herr error
	)

	switch req.MessageType {
	case "attach_request":
		resp, herr = h.attachRequest(ctx, enb, ue, t, &req)
	case "authentication_response":
		resp, herr = h.authenticationResponse(ctx, enb, ue, t, &req)
	case "authentication_failure":
		resp, herr = h.authenticationFailure(ctx, enb, ue, t, &req)
	case "identity_response":
		resp, herr = h.identityResponse(ctx, enb, ue, t)
	case "inject_nas":
		resp, herr = h.injectNAS(ctx, enb, ue, t, &req)
	case "detach_request":
		resp, herr = h.detach(ctx, enb, ue, t, &req)
	case "release_request":
		resp, herr = h.releaseRequest(ctx, enb, ue, t, &req)
	case "service_request":
		resp, herr = h.serviceRequest(ctx, enb, ue, t, &req)
	case "tracking_area_update":
		resp, herr = h.trackingAreaUpdate(ctx, enb, ue, t, &req)
	case "ue_capability_info":
		resp, herr = h.ueCapabilityInfo(ctx, enb, ue, t, &req)
	case "path_switch":
		resp, herr = h.pathSwitch(ctx, enb, ue, t, &req)
	case "handover_required":
		resp, herr = h.handoverRequired(ue, t, &req)
	case "handover_cancel":
		resp, herr = h.handoverCancel(ctx, ue, t, &req)
	case "enb_status_transfer":
		resp, herr = h.enbStatusTransfer(ue, t, &req)
	case "error_indication":
		resp, herr = h.errorIndication(ctx, ue, t, &req)
	case "initial_context_setup_failure":
		resp, herr = h.initialContextSetupFailure(ue, t, &req)
	case "modify_response":
		resp, herr = h.modifyResponse(ue, t, &req)
	case "pdn_connectivity":
		resp, herr = h.pdnConnectivity(ctx, enb, ue, t, &req)
	case "pdn_disconnect":
		resp, herr = h.pdnDisconnect(ctx, enb, ue, t, &req)
	case "modify_eps_bearer_context_accept":
		resp, herr = h.modifyBearerAccept(enb, ue, t, &req)
	case "deactivate_eps_bearer_context_accept":
		resp, herr = h.deactivateBearerAccept(enb, ue, t, &req)
	case "status_esm":
		resp, herr = h.statusESM(enb, ue, t, &req)
	case "reset":
		resp, herr = h.reset(ctx, ue, t, &req)
	case "security_mode_complete":
		resp, herr = h.securityModeComplete(ctx, enb, ue, t, &req)
	case "security_mode_reject":
		resp, herr = h.securityModeReject(ctx, enb, ue, t, &req)
	case "attach_complete":
		resp, herr = h.attachComplete(ctx, enb, ue, t)
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

func (h *Handler) attachRequest(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	if req.RawNASPDU != nil {
		return h.attachRequestRaw(ctx, enb, ue, t, *req.RawNASPDU)
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
		// A GUTI from this PLMN with an M-TMSI the MME never allocated: it cannot be
		// mapped to an IMSI, so the MME must run the Identity procedure (§5.4.4).
		params.GUTI = &naseps.GUTIParams{MCC: enb.MCC, MNC: enb.MNC, MMEGroupID: 1, MMECode: 1, MTMSI: 0x0BADF00D}
	}

	ar, err := naseps.BuildAttachRequest(params)
	if err != nil {
		return nil, err
	}

	init, err := s1ap.BuildInitialUEMessage(s1ap.InitialUEMessageParams{
		ENBUES1APID: ue.ENBUES1APID, NASPDU: ar, MCC: enb.MCC, MNC: enb.MNC, TAC: enb.TAC, CellID: 1,
	})
	if err != nil {
		return nil, err
	}

	if err := t.Send(init, false); err != nil {
		return nil, err
	}

	dl, err := h.waitDownlink(ctx, t, ue, "DownlinkNASTransport")
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

	// Stash the challenge so authentication_response can compute RES.
	ue.RAND, _ = hex.DecodeString(nas.RAND)
	ue.AUTN, _ = hex.DecodeString(nas.AUTN)
	if nas.KSI != nil {
		ue.KSI = uint8(*nas.KSI)
	}

	return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
}

// attachRequestRaw sends an arbitrary NAS PDU in the Initial UE Message. The MME
// may drop a malformed PDU without reply, so a wait timeout is not an error.
func (h *Handler) attachRequestRaw(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, rawHex string) (*SendENBNASResponse, error) {
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "raw_nas_pdu must be hex: %v", err)
	}

	init, err := s1ap.BuildInitialUEMessage(s1ap.InitialUEMessageParams{
		ENBUES1APID: ue.ENBUES1APID, NASPDU: raw, MCC: enb.MCC, MNC: enb.MNC, TAC: enb.TAC, CellID: 1,
	})
	if err != nil {
		return nil, err
	}

	if err := t.Send(init, false); err != nil {
		return nil, err
	}

	dl := h.waitDownlinkTolerant(ctx, t, ue, "DownlinkNASTransport", "UEContextReleaseCommand", "ErrorIndication")
	if dl == nil {
		return &SendENBNASResponse{}, nil
	}

	learnMMEID(ue, dl)

	var nas *naseps.NASResponse
	if dl.NASPDU != nil {
		if plain, perr := nasPDUBytes(dl); perr == nil {
			nas, _ = naseps.Decode(plain)
		}
	}

	return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
}

func (h *Handler) authenticationResponse(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
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

	if err := h.sendUplink(enb, ue, t, pdu); err != nil {
		return nil, err
	}

	dl, err := h.waitDownlink(ctx, t, ue, "DownlinkNASTransport")
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

	// A plain downlink means the MME did not accept the response: an
	// Authentication Reject (wrong RES, §5.4.2.5) or an Identity Request. Return
	// it as-is — no security context is established.
	if sht == naseps.SHTPlain {
		nas, derr := naseps.Decode(nasBytes)
		if derr != nil {
			return nil, derr
		}

		return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
	}

	// The Security Mode Command is integrity-protected but not ciphered, so read
	// the selected algorithms from the inner payload before deriving the keys.
	inner, err := naseps.PeekProtectedPayload(nasBytes)
	if err != nil {
		return nil, err
	}

	smc, err := naseps.Decode(inner)
	if err != nil {
		return nil, err
	}

	if smc.CipheringAlgorithm == nil || smc.IntegrityAlgorithm == nil {
		return nil, fmt.Errorf("expected Security Mode Command, got %s", smc.MessageType)
	}

	ue.EEA = uint8(*smc.CipheringAlgorithm)
	ue.EIA = uint8(*smc.IntegrityAlgorithm)

	if ue.KnasEnc, ue.KnasInt, err = crypto.DeriveEPSNASKeys(ue.Kasme, ue.EEA, ue.EIA); err != nil {
		return nil, err
	}

	ue.SecurityActive = true
	ue.ULCount = 0
	ue.DLCount = 0

	// Verify the MME's NAS-MAC under our independently-derived keys (DL COUNT 0).
	_, verr := naseps.Unprotect(nasBytes, ue.NextDL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	verified := verr == nil

	return &SendENBNASResponse{S1AP: dl, NAS: smc, MACVerified: &verified}, nil
}

func (h *Handler) identityResponse(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport) (*SendENBNASResponse, error) {
	pdu, err := naseps.BuildIdentityResponse(ue.IMSI)
	if err != nil {
		return nil, err
	}

	if err := h.sendUplink(enb, ue, t, pdu); err != nil {
		return nil, err
	}

	dl, err := h.waitDownlink(ctx, t, ue, "DownlinkNASTransport")
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

	// With the IMSI in hand the MME challenges; adopt the challenge for the
	// following authentication_response.
	if nas.MessageType == "authentication_request" {
		ue.RAND, _ = hex.DecodeString(nas.RAND)
		ue.AUTN, _ = hex.DecodeString(nas.AUTN)
	}

	return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
}

func (h *Handler) authenticationFailure(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	if req.Cause == nil {
		return nil, httpErrorf(http.StatusBadRequest, "cause is required for authentication_failure")
	}

	cause := uint8(*req.Cause)

	// A synch failure carries the AUTS re-synchronisation token (TS 24.301
	// §5.4.2.6 c); the MME forwards it to the HSS to re-sync the SQN.
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

	if err := h.sendUplink(enb, ue, t, pdu); err != nil {
		return nil, err
	}

	dl, err := h.waitDownlink(ctx, t, ue, "DownlinkNASTransport")
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

	// On a synch-failure re-sync the MME re-challenges with a fresh vector; adopt
	// the new challenge so a following authentication_response uses it.
	if nas.MessageType == "authentication_request" {
		ue.RAND, _ = hex.DecodeString(nas.RAND)
		ue.AUTN, _ = hex.DecodeString(nas.AUTN)
	}

	return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
}

func (h *Handler) securityModeComplete(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	if !ue.SecurityActive {
		return nil, fmt.Errorf("no NAS security context; run authentication_response first")
	}

	smc, err := naseps.BuildSecurityModeComplete(nil)
	if err != nil {
		return nil, err
	}

	protected, err := naseps.Protect(smc, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, err
	}

	if req.CorruptMAC {
		// Flip the first octet of the 4-octet NAS-MAC (the message is
		// header‖MAC‖seq‖payload). The MME must discard it (§4.4.4).
		protected[1] ^= 0xff
	}

	if err := h.sendUplink(enb, ue, t, protected); err != nil {
		return nil, err
	}

	// A discarded message yields no Initial Context Setup; report what (if
	// anything) arrived so the caller can assert the MME did not proceed.
	if req.CorruptMAC {
		return &SendENBNASResponse{S1AP: h.waitDownlinkTolerant(ctx, t, ue, "InitialContextSetupRequest")}, nil
	}

	dl, err := h.waitDownlink(ctx, t, ue, "InitialContextSetupRequest")
	if err != nil {
		return nil, err
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, fmt.Errorf("unprotect attach accept: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
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
		ue.UPFIP = e.TransportLayerAddress
	}

	// The eNB advertises its own downlink TEID in the Initial Context Setup
	// Response (we use the eNB UE S1AP ID); the UE IP comes from the Attach Accept.
	ue.DLTeid = ue.ENBUES1APID
	ue.UEIP = ueIPFromPDNAddress(nas.PDNAddress)

	return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
}

// ueIPFromPDNAddress extracts the UE IPv4 from an Attach Accept PDN address (hex):
// a PDN-type octet (1 = IPv4) followed by the 4 address octets (TS 24.301
// §9.9.4.9). Returns "" if not an IPv4 address.
func ueIPFromPDNAddress(pdnHex string) string {
	b, err := hex.DecodeString(pdnHex)
	if err != nil || len(b) < 5 || b[0] != naseps.PDNTypeIPv4 {
		return ""
	}

	return net.IP(b[1:5]).String()
}

// emmCauseSecurityCapMismatch is EMM cause #23 (UE security capabilities
// mismatch) for a Security Mode Reject (TS 24.301 §5.4.3.5).
const emmCauseSecurityCapMismatch uint8 = 23

func (h *Handler) securityModeReject(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	cause := emmCauseSecurityCapMismatch
	if req.Cause != nil {
		cause = uint8(*req.Cause)
	}

	// The Security Mode Reject is sent unprotected: the UE could not take the new
	// security context into use (TS 24.301 §5.4.3.5).
	pdu, err := naseps.BuildSecurityModeReject(cause)
	if err != nil {
		return nil, err
	}

	if err := h.sendUplink(enb, ue, t, pdu); err != nil {
		return nil, err
	}

	// The MME must abort and release the NAS signalling connection (§5.4.3.5).
	dl, err := h.waitDownlink(ctx, t, ue, "UEContextReleaseCommand")
	if err != nil {
		return nil, err
	}

	return &SendENBNASResponse{S1AP: dl}, nil
}

func (h *Handler) attachComplete(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport) (*SendENBNASResponse, error) {
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

	protected, err := naseps.Protect(ac, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, err
	}

	if err := h.sendUplink(enb, ue, t, protected); err != nil {
		return nil, err
	}

	// Once it has the Attach Complete, the MME may send an EMM Information message
	// (the operator network name). Consume it so the downlink NAS COUNT stays in
	// step for any following procedure; its absence is fine.
	wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	resp := &SendENBNASResponse{}

	if dl := h.waitDownlinkTolerant(wctx, t, ue, "DownlinkNASTransport"); dl != nil && dl.NASPDU != nil {
		if nasBytes, berr := nasPDUBytes(dl); berr == nil {
			if plain, perr := naseps.Unprotect(nasBytes, ue.NextDL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc); perr == nil {
				resp.S1AP = dl
				resp.NAS, _ = naseps.Decode(plain)
			}
		}
	}

	return resp, nil
}

func (h *Handler) sendUplink(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, nasPDU []byte) error {
	ul, err := s1ap.BuildUplinkNASTransport(s1ap.UplinkNASTransportParams{
		MMEUES1APID: ue.MMEUES1APID, ENBUES1APID: ue.ENBUES1APID, NASPDU: nasPDU,
		MCC: enb.MCC, MNC: enb.MNC, TAC: enb.TAC, CellID: 1,
	})
	if err != nil {
		return err
	}

	ue.LastUplinkNAS = nasPDU

	return t.Send(ul, false)
}

// injectNAS sends an Uplink NAS Transport with an attacker-controlled NAS PDU
// and, optionally, a forged MME-UE-S1AP-ID, to probe the MME's UE-association
// validation and replay protection. No reply (the MME discarding it) is a valid
// outcome.
// ueCapabilityInfo sends a UE Capability Info Indication (one-way; no MME reply).
// The MME stores the radio capability for replay in a later Initial Context Setup
// Request (TS 23.401 §5.11.2).
func (h *Handler) ueCapabilityInfo(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
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

	// No response is expected on success; a forged or inconsistent UE S1AP ID must
	// draw an Error Indication (TS 36.413 §10.6). Match by type, since the
	// indication echoes the forged IDs rather than this UE's.
	wctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	resp, _ := t.WaitForMessage(wctx, "ErrorIndication")

	return &SendENBNASResponse{S1AP: resp}, nil
}

// forgeIDs returns the UE's MME- and eNB-UE-S1AP-IDs, each replaced by its
// override when the request sets one (for AP-ID fuzzing, TS 36.413 §10.6).
func forgeIDs(ue *store.UEEPSContext, req *SendENBNASRequest) (uint32, uint32) {
	mmeID, enbID := ue.MMEUES1APID, ue.ENBUES1APID
	if req.MMEUES1APIDOverride != nil {
		mmeID = *req.MMEUES1APIDOverride
	}

	if req.ENBUES1APIDOverride != nil {
		enbID = *req.ENBUES1APIDOverride
	}

	return mmeID, enbID
}

// pathSwitch emulates a target eNB issuing a PATH SWITCH REQUEST after an X2
// handover: it switches the UE's default-bearer downlink to a fresh endpoint and
// expects a PATH SWITCH REQUEST ACKNOWLEDGE carrying a fresh {NH, NCC}, or a
// PATH SWITCH REQUEST FAILURE when the path cannot be switched (TS 36.413
// §9.1.5.8, key chain per TS 33.401 §7.2.8).
func (h *Handler) pathSwitch(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
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

	// Report the same UE security capabilities the UE advertised at attach (the
	// MME's stored values), so a matching Path Switch draws no replay. The S1AP
	// encoding drops the EEA0/EIA0 bit, so shift the network capability octets left.
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
		TargetTEID:                    ue.ENBUES1APID + 0x1000, // a fresh target downlink TEID
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

	dl := h.waitDownlinkTolerant(ctx, t, ue, "PathSwitchRequestAcknowledge", "PathSwitchRequestFailure")
	if dl == nil {
		return &SendENBNASResponse{}, nil
	}

	return &SendENBNASResponse{S1AP: dl}, nil
}

// reset emulates an eNB-initiated S1 RESET (TS 36.413 §8.7.1): a full reset of
// the S1 interface, or a partial reset naming this UE's connection. The MME must
// release the affected UE-associated connections and reply with a Reset
// Acknowledge — which, for a partial reset, echoes the connection list.
func (h *Handler) reset(ctx context.Context, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	var connections []s1ap.ResetConnection
	if !req.ResetAll {
		connections = []s1ap.ResetConnection{{MMEUES1APID: ue.MMEUES1APID, ENBUES1APID: ue.ENBUES1APID}}
	}

	pdu, err := s1ap.BuildReset(req.ResetAll, connections)
	if err != nil {
		return nil, err
	}

	if err := t.Send(pdu, false); err != nil {
		return nil, err
	}

	// The Reset Acknowledge is non-UE-associated (a full reset carries no UE ID),
	// so match by message type rather than by this UE's S1AP IDs.
	resp, err := t.WaitForMessage(ctx, "ResetAcknowledge")
	if err != nil {
		return &SendENBNASResponse{}, nil
	}

	return &SendENBNASResponse{S1AP: resp}, nil
}

// pdnConnectivity drives a UE-requested additional PDN connection (TS 24.301
// §6.5.1): it sends a (protected) standalone PDN Connectivity Request for the
// requested APN; the MME accepts by sending the Activate Default EPS Bearer
// Context Request in an E-RAB Setup Request — answered with E-RAB Setup Response
// and Activate Default Accept — or rejects with a PDN Connectivity Reject.
func (h *Handler) pdnConnectivity(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
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

	protected, err := naseps.Protect(esm, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, err
	}

	if err := h.sendUplink(enb, ue, t, protected); err != nil {
		return nil, err
	}

	// The MME accepts via E-RAB Setup Request (carrying the Activate Default), or
	// rejects with a PDN Connectivity Reject in a Downlink NAS Transport. A
	// discarded request yields no reply.
	dl := h.waitDownlinkTolerant(ctx, t, ue, "ERABSetupRequest", "DownlinkNASTransport")
	if dl == nil {
		return &SendENBNASResponse{}, nil
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, fmt.Errorf("unprotect pdn connectivity reply: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	// A reject (or any non-activation reply) is returned as-is for assertion.
	if dl.MessageType != "ERABSetupRequest" || nas.MessageType != "activate_default_eps_bearer_context_request" {
		return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
	}

	if err := h.acceptAdditionalBearer(enb, ue, t, dl, nas); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
}

// acceptAdditionalBearer completes a UE-requested PDN connection: it records the
// new bearer, acknowledges the radio leg with an E-RAB Setup Response, and the
// session with an Activate Default EPS Bearer Context Accept (TS 24.301 §6.5.1.3).
func (h *Handler) acceptAdditionalBearer(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, dl *s1ap.S1APResponse, nas *naseps.NASResponse) error {
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
		DLTeid: (ue.ENBUES1APID << 8) | uint32(ebi), // distinct per (UE, bearer)
	}

	if len(dl.ERABSetupItems) > 0 {
		e := dl.ERABSetupItems[0]
		bearer.ULTeid = e.GTPTEID
		bearer.UPFIP = e.TransportLayerAddress
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

	protectedAccept, err := naseps.Protect(accept, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return err
	}

	return h.sendUplink(enb, ue, t, protectedAccept)
}

// pdnDisconnect drives a UE-requested PDN disconnect (TS 24.301 §6.5.2): it sends
// a (protected) PDN Disconnect Request naming the linked bearer; the MME accepts
// by sending a Deactivate EPS Bearer Context Request — answered with Deactivate
// Accept — or rejects with a PDN Disconnect Reject.
func (h *Handler) pdnDisconnect(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
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

	protected, err := naseps.Protect(esm, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, err
	}

	if err := h.sendUplink(enb, ue, t, protected); err != nil {
		return nil, err
	}

	// Disconnecting an additional PDN keeps the UE connected, so the MME carries
	// the Deactivate in an E-RAB Release Command that also releases the radio
	// bearer (TS 23.401 §5.10.3); a reject arrives as a Downlink NAS Transport.
	dl := h.waitDownlinkTolerant(ctx, t, ue, "ERABReleaseCommand", "DownlinkNASTransport")
	if dl == nil {
		return &SendENBNASResponse{}, nil
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, fmt.Errorf("unprotect pdn disconnect reply: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	// The MME accepts by deactivating the bearer; acknowledge it and drop the PDN.
	if nas.MessageType == "deactivate_eps_bearer_context_request" && nas.EPSBearerIdentity != nil {
		deactEBI := uint8(*nas.EPSBearerIdentity)
		deactPTI := uint8(0)
		if nas.BearerPTI != nil {
			deactPTI = uint8(*nas.BearerPTI)
		}

		// Confirm the radio-bearer release first when it rode an E-RAB Release Command.
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

		protectedAccept, perr := naseps.Protect(accept, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
		if perr != nil {
			return nil, perr
		}

		if serr := h.sendUplink(enb, ue, t, protectedAccept); serr != nil {
			return nil, serr
		}

		delete(ue.Bearers, deactEBI)
	}

	return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
}

// esmCauseProtocolErrorUnspec is ESM cause #111 (TS 24.301 §9.9.4.4), the default
// for a UE-sent esm_status.
const esmCauseProtocolErrorUnspec uint8 = 111

// statusESM sends an ESM STATUS reporting an ESM protocol error for a bearer
// (TS 24.301 §6.7). ESM cause #43 makes the MME deactivate the bearer.
func (h *Handler) statusESM(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
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

	return h.sendESM(enb, ue, t, esm)
}

// modifyBearerAccept acknowledges a network-initiated bearer modification
// (TS 24.301 §6.4.3.3).
func (h *Handler) modifyBearerAccept(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildModifyEPSBearerContextAccept(esmBearerID(ue, req), esmPTI(req))
	if err != nil {
		return nil, err
	}

	return h.sendESM(enb, ue, t, esm)
}

// deactivateBearerAccept acknowledges a network-initiated bearer deactivation
// (TS 24.301 §6.4.4.3).
func (h *Handler) deactivateBearerAccept(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildDeactivateEPSBearerContextAccept(esmBearerID(ue, req), esmPTI(req))
	if err != nil {
		return nil, err
	}

	return h.sendESM(enb, ue, t, esm)
}

func (h *Handler) sendESM(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, esm []byte) (*SendENBNASResponse, error) {
	protected, err := naseps.Protect(esm, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, err
	}

	if err := h.sendUplink(enb, ue, t, protected); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{}, nil
}

func esmBearerID(ue *store.UEEPSContext, req *SendENBNASRequest) uint8 {
	if req.EPSBearerIdentity != nil {
		return *req.EPSBearerIdentity
	}

	return ue.EPSBearerID
}

func esmPTI(req *SendENBNASRequest) uint8 {
	if req.PTI != nil {
		return *req.PTI
	}

	return 0
}

// errorIndication sends an ERROR INDICATION for the UE's connection (TS 36.413
// §8.7.2); the MME's reaction to it is implementation-specific.
func (h *Handler) errorIndication(ctx context.Context, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	encoded, err := s1ap.BuildErrorIndication(sourceMMEID(ue, req), sourceENBID(ue, req), 0) // radio-network unspecified
	if err != nil {
		return nil, err
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	resp := h.waitDownlinkTolerant(ctx, t, ue, "UEContextReleaseCommand", "ErrorIndication")

	return &SendENBNASResponse{S1AP: resp}, nil
}

// initialContextSetupFailure replies to an Initial Context Setup Request with a
// failure (TS 36.413 §8.3.1.4); the MME releases the UE context. Send-only.
func (h *Handler) initialContextSetupFailure(ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	encoded, err := s1ap.BuildInitialContextSetupFailure(sourceMMEID(ue, req), sourceENBID(ue, req), 0) // radio-network unspecified
	if err != nil {
		return nil, err
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{}, nil
}

// modifyResponse confirms a network-initiated E-RAB modification (TS 36.413
// §8.2.2). Send-only; the MME completes the procedure on the NAS Modify Accept.
func (h *Handler) modifyResponse(ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	encoded, err := s1ap.BuildERABModifyResponse(ue.MMEUES1APID, ue.ENBUES1APID, []uint8{esmBearerID(ue, req)})
	if err != nil {
		return nil, err
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{}, nil
}

// trackingAreaUpdate sends a (protected) Tracking Area Update Request from a
// connected UE and handles the MME's reply: a TAU Accept (acknowledged with TAU
// Complete when it reallocates the GUTI) or a TAU Reject (TS 24.301 §5.5.3).
func (h *Handler) trackingAreaUpdate(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	guti := naseps.GUTIParams{
		MCC: ue.GUTIMCC, MNC: ue.GUTIMNC,
		MMEGroupID: ue.GUTIGroupID, MMECode: ue.GUTICode, MTMSI: ue.GUTIMTMSI,
	}

	tau, err := naseps.BuildTrackingAreaUpdateRequest(req.EPSUpdateType, false, ue.KSI, guti)
	if err != nil {
		return nil, err
	}

	count := ue.NextUL()
	if req.NASCountOverride != nil {
		count = *req.NASCountOverride
	}

	protected, err := naseps.Protect(tau, naseps.SHTIntegrityProtectedCiphered, count, ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, err
	}

	if req.CorruptMAC {
		protected[1] ^= 0xff
	}

	if err := h.sendUplink(enb, ue, t, protected); err != nil {
		return nil, err
	}

	// A discarded (bad-MAC) TAU yields no reply; that is a valid outcome.
	dl := h.waitDownlinkTolerant(ctx, t, ue, "DownlinkNASTransport")
	if dl == nil {
		return &SendENBNASResponse{}, nil
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	// A TAU Reject is sent plain (§4.4.4.2); a TAU Accept is protected.
	sht, err := naseps.SecurityHeader(nasBytes)
	if err != nil {
		return nil, err
	}

	if sht == naseps.SHTPlain {
		nas, derr := naseps.Decode(nasBytes)
		return &SendENBNASResponse{S1AP: dl, NAS: nas}, derr
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, fmt.Errorf("unprotect TAU accept: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	// A reallocated GUTI must be acknowledged with TAU Complete (§5.5.3.2.4).
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

		protectedC, perr := naseps.Protect(complete, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
		if perr != nil {
			return nil, perr
		}

		if serr := h.sendUplink(enb, ue, t, protectedC); serr != nil {
			return nil, serr
		}
	}

	return &SendENBNASResponse{S1AP: dl, NAS: nas}, nil
}

// releaseRequest drives the eNB-initiated S1 release that moves the UE to
// ECM-IDLE: it sends a UE Context Release Request, expects the MME's Release
// Command, and acknowledges with Release Complete. The NAS security context is
// retained for a following Service Request.
func (h *Handler) releaseRequest(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	mmeID, enbID := forgeIDs(ue, req)

	cause := s1ap.CauseRadioUserInactivity
	if req.ReleaseCause != nil {
		cause = uint8(*req.ReleaseCause)
	}

	rr, err := s1ap.BuildUEContextReleaseRequest(mmeID, enbID, cause)
	if err != nil {
		return nil, err
	}

	if err := t.Send(rr, false); err != nil {
		return nil, err
	}

	// A forged or inconsistent UE S1AP ID must draw an Error Indication, not a
	// Release Command (TS 36.413 §10.6); match by type since it echoes the
	// forged IDs.
	if req.MMEUES1APIDOverride != nil || req.ENBUES1APIDOverride != nil {
		resp, _ := t.WaitForMessage(ctx, "ErrorIndication", "UEContextReleaseCommand")
		return &SendENBNASResponse{S1AP: resp}, nil
	}

	// The MME answers with a Release Command, or — when the S1 context is already
	// gone (a repeated release) — an Error Indication (TS 36.413 §10.6). No reply
	// is a valid outcome.
	dl, err := h.waitDownlink(ctx, t, ue, "UEContextReleaseCommand", "ErrorIndication")
	if err != nil {
		return &SendENBNASResponse{}, nil
	}

	if dl.MessageType != "UEContextReleaseCommand" {
		return &SendENBNASResponse{S1AP: dl}, nil
	}

	comp, err := s1ap.BuildUEContextReleaseComplete(ue.MMEUES1APID, ue.ENBUES1APID)
	if err != nil {
		return nil, err
	}

	if err := t.Send(comp, false); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{S1AP: dl}, nil
}

// serviceRequest re-establishes an idle UE's connection: it sends a Service
// Request (short-MAC) in an Initial UE Message identified by the UE's S-TMSI. The
// MME re-establishes the bearer (Initial Context Setup Request) or refuses
// (Service Reject, TS 24.301 §5.6.1).
func (h *Handler) serviceRequest(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	count := ue.NextUL()
	if req.NASCountOverride != nil {
		count = *req.NASCountOverride
	}

	sr, err := naseps.BuildServiceRequest(ue.KSI, count, ue.KnasInt, ue.EIA)
	if err != nil {
		return nil, err
	}

	if req.CorruptMAC {
		sr[3] ^= 0xff // corrupt the short MAC
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

	// A Service Request with a bad short-MAC may be silently discarded, so no
	// reply is a valid outcome.
	dl := h.waitDownlinkTolerant(ctx, t, ue, "InitialContextSetupRequest", "DownlinkNASTransport")
	if dl == nil {
		return &SendENBNASResponse{}, nil
	}

	learnMMEID(ue, dl)
	resp := &SendENBNASResponse{S1AP: dl}

	switch dl.MessageType {
	case "InitialContextSetupRequest":
		// Re-established; acknowledge the bearer setup.
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
		// A Service Reject is sent plain (TS 24.301 §5.6.1.5).
		if dl.NASPDU != nil {
			if plain, berr := nasPDUBytes(dl); berr == nil {
				resp.NAS, _ = naseps.Decode(plain)
			}
		}
	}

	return resp, nil
}

// detach sends a UE-originating Detach Request. A normal detach elicits a Detach
// Accept and a UE Context Release; a switch-off detach elicits only the release
// (TS 24.301 §5.5.2).
func (h *Handler) detach(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	guti := naseps.GUTIParams{
		MCC: ue.GUTIMCC, MNC: ue.GUTIMNC,
		MMEGroupID: ue.GUTIGroupID, MMECode: ue.GUTICode, MTMSI: ue.GUTIMTMSI,
	}

	pdu, err := naseps.BuildDetachRequest(req.SwitchOff, ue.KSI, guti)
	if err != nil {
		return nil, err
	}

	protected, err := naseps.Protect(pdu, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil, err
	}

	if err := h.sendUplink(enb, ue, t, protected); err != nil {
		return nil, err
	}

	if req.SwitchOff {
		// No Detach Accept; the MME just releases the connection.
		return &SendENBNASResponse{S1AP: h.waitDownlinkTolerant(ctx, t, ue, "UEContextReleaseCommand")}, nil
	}

	dl, err := h.waitDownlink(ctx, t, ue, "DownlinkNASTransport")
	if err != nil {
		return nil, err
	}

	resp := &SendENBNASResponse{S1AP: dl}

	if dl.NASPDU != nil {
		nasBytes, berr := nasPDUBytes(dl)
		if berr != nil {
			return nil, berr
		}

		plain, perr := naseps.Unprotect(nasBytes, ue.NextDL(), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
		if perr != nil {
			return nil, fmt.Errorf("unprotect detach accept: %w", perr)
		}

		if resp.NAS, err = naseps.Decode(plain); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (h *Handler) injectNAS(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
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

	// Accept any of the plausible reactions (an Error Indication, a release, a
	// downlink) without an ID matcher, since a forged ID may not echo this UE's.
	resp, err := t.WaitForMessage(ctx, "DownlinkNASTransport", "ErrorIndication", "UEContextReleaseCommand")
	if err != nil {
		return &SendENBNASResponse{}, nil
	}

	return &SendENBNASResponse{S1AP: resp}, nil
}

// waitDownlinkTolerant is waitDownlink for adversarial paths where no reply is a
// valid outcome: a timeout returns nil rather than an error.
func (h *Handler) waitDownlinkTolerant(ctx context.Context, t *transport.S1APTransport, ue *store.UEEPSContext, types ...string) *s1ap.S1APResponse {
	resp, err := h.waitDownlink(ctx, t, ue, types...)
	if err != nil {
		return nil
	}

	return resp
}

func (h *Handler) waitDownlink(ctx context.Context, t *transport.S1APTransport, ue *store.UEEPSContext, types ...string) (*s1ap.S1APResponse, error) {
	match := func(r *s1ap.S1APResponse) bool {
		return r.ENBUES1APID != nil && *r.ENBUES1APID == int64(ue.ENBUES1APID)
	}

	return t.WaitForMessageMatching(ctx, match, types...)
}

func learnMMEID(ue *store.UEEPSContext, resp *s1ap.S1APResponse) {
	if resp.MMEUES1APID != nil {
		ue.MMEUES1APID = uint32(*resp.MMEUES1APID)
		ue.MMEIDKnown = true
	}
}

func nasPDUBytes(resp *s1ap.S1APResponse) ([]byte, error) {
	if resp.NASPDU == nil {
		return nil, fmt.Errorf("downlink %s carries no NAS PDU", resp.MessageType)
	}

	return hex.DecodeString(*resp.NASPDU)
}
