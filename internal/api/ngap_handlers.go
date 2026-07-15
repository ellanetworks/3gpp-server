// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/ellanetworks/3gpp-server/internal/gtpu"
	nasCodec "github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap/ngapType"
)

func (h *Handler) SendNGAP(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGNB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	ue, ok := gnb.GetUE(ueID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return
	}

	t, ok := h.Transports[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no active SCTP transport")
		return
	}

	var req SendNGAPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	switch req.MessageType {
	case "registration_request":
		handleRegistrationRequest(w, r, gnb, ue, t, &req)
	case "authentication_response":
		handleAuthenticationResponse(w, r, gnb, ue, t, &req)
	case "security_mode_complete":
		handleSecurityModeComplete(w, r, gnb, ue, t, &req)
	case "registration_complete":
		handleRegistrationComplete(w, r, gnb, ue, t, &req)
	case "pdu_session_establishment_request":
		handlePDUSessionEstablishmentRequest(w, r, gnb, ue, t, h.GTPU[gnbID], &req)
	case "deregistration_request":
		handleDeregistrationRequest(w, r, gnb, ue, t, &req)
	case "ue_context_release_request":
		handleUEContextReleaseRequest(w, r, gnb, ue, t, &req)
	case "service_request":
		handleServiceRequest(w, r, gnb, ue, t, &req)
	case "inject_nas":
		handleInjectNAS(w, r, gnb, ue, t, &req)
	case "error_indication":
		handleErrorIndication(w, r, gnb, ue, t, &req)
	case "ue_capability_info":
		handleUECapabilityInfo(w, r, gnb, ue, t, &req)
	case "identity_response":
		handleIdentityResponse(w, r, gnb, ue, t, &req)
	case "pdu_session_release_request":
		handlePDUSessionReleaseRequest(w, r, gnb, ue, t, &req)
	case "pdu_session_modification_request":
		handlePDUSessionModificationRequest(w, r, gnb, ue, t, &req)
	case "pdu_session_release_complete":
		handlePDUSessionReleaseComplete(w, r, gnb, ue, t, &req)
	case "pdu_session_modification_complete":
		handlePDUSessionModificationComplete(w, r, gnb, ue, t, &req)
	case "pdu_session_modification_command_reject":
		handlePDUSessionModificationCommandReject(w, r, gnb, ue, t, &req)
	case "status_5gsm":
		handleStatus5GSM(w, r, gnb, ue, t, &req)
	case "authentication_failure":
		handleAuthenticationFailure(w, r, gnb, ue, t, &req)
	case "security_mode_reject":
		handleSecurityModeReject(w, r, gnb, ue, t, &req)
	case "handover_required":
		handleHandoverRequired(w, r, gnb, ue, t, &req)
	case "ran_status_transfer":
		handleRANStatusTransfer(w, r, gnb, ue, t, &req)
	case "handover_cancel":
		handleHandoverCancel(w, r, gnb, ue, t, &req)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported message_type: %s", req.MessageType))
	}
}

func (h *Handler) SendGnBNGAP(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	gnb, err := h.Store.GetGNB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	t, ok := h.Transports[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no active SCTP transport")
		return
	}

	var req SendGnBNGAPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.RawNGAPPDU != nil {
		handleRawNGAP(w, r, t, &req)
		return
	}

	switch req.MessageType {
	case "ng_reset":
		handleNGReset(w, r, gnb, t, &req)
	case "handover_request_acknowledge":
		handleHandoverRequestAcknowledge(w, t, &req)
	case "handover_failure":
		handleHandoverFailure(w, t, &req)
	case "handover_notify":
		handleHandoverNotify(w, gnb, t, &req)
	case "path_switch_request":
		handlePathSwitchRequest(w, r, gnb, t, &req)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported message_type: %s", req.MessageType))
	}
}

func effectiveRanID(req *SendNGAPRequest, ue *store.UEContext) int64 {
	if req != nil && req.RanUeNgapIDOverride != nil {
		return *req.RanUeNgapIDOverride
	}

	return ue.RanUeNgapID
}

func effectiveAmfID(req *SendNGAPRequest, ue *store.UEContext) int64 {
	if req != nil && req.AmfUeNgapIDOverride != nil {
		return *req.AmfUeNgapIDOverride
	}

	return ue.AmfUeNgapID
}

// An amfID of 0 means the AMF has not assigned one yet, so it cannot match.
func ueNGAPMatcher(ranID, amfID int64) func(*ngap.NGAPResponse) bool {
	return func(resp *ngap.NGAPResponse) bool {
		var msgRan, msgAmf *int64

		for i := range resp.IEs {
			if resp.IEs[i].RanUeNgapID != nil {
				msgRan = resp.IEs[i].RanUeNgapID
			}

			if resp.IEs[i].AmfUeNgapID != nil {
				msgAmf = resp.IEs[i].AmfUeNgapID
			}
		}

		if msgRan == nil && msgAmf == nil {
			return true
		}

		if msgRan != nil && *msgRan == ranID {
			return true
		}

		if msgAmf != nil && amfID != 0 && *msgAmf == amfID {
			return true
		}

		return false
	}
}

func (h *Handler) AwaitUEMessage(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGNB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	ue, ok := gnb.GetUE(ueID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return
	}

	t, ok := h.Transports[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no active SCTP transport")
		return
	}

	req, ok := decodeAwaitRequest(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), req.timeout)
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(ue.RanUeNgapID, ue.AmfUeNgapID), req.MessageTypes...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.MessageTypes, err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp, NAS: decodeNASFromNGAP(ue, ngapResp)})
}

func decodeNASFromNGAP(ue *store.UEContext, ngapResp *ngap.NGAPResponse) *nasCodec.NASResponse {
	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		if ie.NasPDU == nil {
			continue
		}

		nasPDUBytes, err := hex.DecodeString(*ie.NasPDU)
		if err != nil {
			continue
		}

		nasResp, _ = nasCodec.DecodeSecuredNAS(ue, nasPDUBytes)
	}

	return nasResp
}

func (h *Handler) AwaitGnBMessage(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	if _, err := h.Store.GetGNB(gnbID); err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	t, ok := h.Transports[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no active SCTP transport")
		return
	}

	req, ok := decodeAwaitRequest(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), req.timeout)
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, req.MessageTypes...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.MessageTypes, err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func handleHandoverRequired(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	if req.TargetGnbID == nil {
		writeError(w, http.StatusBadRequest, "target_gnb_id is required for handover_required")
		return
	}

	pduSessionID := pduSessionIDForRelease(ue)

	amfUeNgapID := ue.AmfUeNgapID
	if req.AmfUeNgapIDOverride != nil {
		amfUeNgapID = *req.AmfUeNgapIDOverride
	}

	ranUeNgapID := ue.RanUeNgapID
	if req.RanUeNgapIDOverride != nil {
		ranUeNgapID = *req.RanUeNgapIDOverride
	}

	pduSessionIDs := []int64{int64(pduSessionID)}
	if len(req.PDUSessionIDs) > 0 {
		pduSessionIDs = req.PDUSessionIDs
	}

	cause := int64(ngap.CauseRadioNetworkHandoverDesirableForRadioReason)
	if req.HandoverRequiredCause != nil {
		cause = *req.HandoverRequiredCause
	}

	encoded, err := ngap.BuildHandoverRequired(amfUeNgapID, ranUeNgapID, *req.TargetGnbID,
		gnb.MCC, gnb.MNC, gnb.TAC, pduSessionIDs, cause)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverRequired: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func handleRANStatusTransfer(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	drbs := make([]ngap.DRBStatusTransferItem, 0, len(req.StatusTransferDRBs))
	for _, d := range req.StatusTransferDRBs {
		drbs = append(drbs, ngap.DRBStatusTransferItem{
			DRBID:    d.DRBID,
			ULPDCPSN: d.ULPDCPSN,
			ULHFN:    d.ULHFN,
			DLPDCPSN: d.DLPDCPSN,
			DLHFN:    d.DLHFN,
		})
	}

	if len(drbs) == 0 {
		drbs = append(drbs, ngap.DRBStatusTransferItem{DRBID: 1})
	}

	encoded, err := ngap.BuildUplinkRANStatusTransfer(effectiveAmfID(req, ue), effectiveRanID(req, ue), drbs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build UplinkRANStatusTransfer: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func handleHandoverCancel(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	amfUeNgapID := ue.AmfUeNgapID
	if req.AmfUeNgapIDOverride != nil {
		amfUeNgapID = *req.AmfUeNgapIDOverride
	}

	ranUeNgapID := ue.RanUeNgapID
	if req.RanUeNgapIDOverride != nil {
		ranUeNgapID = *req.RanUeNgapIDOverride
	}

	cause := ngap.CauseRadioNetworkHandoverCancelled
	if req.HandoverCancelCause != nil {
		cause = *req.HandoverCancelCause
	}

	encoded, err := ngap.BuildHandoverCancel(amfUeNgapID, ranUeNgapID, cause)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverCancel: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, "HandoverCancelAcknowledge", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for HandoverCancelAcknowledge: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func handleHandoverRequestAcknowledge(w http.ResponseWriter, t *transport.NGAPTransport, req *SendGnBNGAPRequest) {
	if req.AmfUeNgapID == nil || req.RanUeNgapID == nil {
		writeError(w, http.StatusBadRequest, "amf_ue_ngap_id and ran_ue_ngap_id are required")
		return
	}

	if len(req.PDUSessions) == 0 {
		writeError(w, http.StatusBadRequest, "pdu_sessions is required for handover_request_acknowledge")
		return
	}

	var sessions []ngap.HandoverAdmittedSession

	for _, ps := range req.PDUSessions {
		dlIP := ps.DLIP
		if dlIP == "" {
			dlIP = "127.0.0.1"
		}

		teid := ps.DLTeid
		if teid == 0 {
			teid = 1
		}

		var rawTransfer []byte

		if ps.RawTransfer != nil {
			decoded, err := hex.DecodeString(*ps.RawTransfer)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_transfer: %v", err))
				return
			}

			rawTransfer = decoded
		}

		sessions = append(sessions, ngap.HandoverAdmittedSession{PDUSessionID: ps.ID, DLTeid: teid, DLIP: dlIP, RawTransfer: rawTransfer})
	}

	encoded, err := ngap.BuildHandoverRequestAcknowledge(*req.AmfUeNgapID, *req.RanUeNgapID, sessions, req.FailedPDUSessions)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverRequestAcknowledge: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func handleHandoverNotify(w http.ResponseWriter, gnb *store.GNBContext, t *transport.NGAPTransport, req *SendGnBNGAPRequest) {
	if req.AmfUeNgapID == nil || req.RanUeNgapID == nil {
		writeError(w, http.StatusBadRequest, "amf_ue_ngap_id and ran_ue_ngap_id are required")
		return
	}

	encoded, err := ngap.BuildHandoverNotify(*req.AmfUeNgapID, *req.RanUeNgapID, gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverNotify: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func handlePathSwitchRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, t *transport.NGAPTransport, req *SendGnBNGAPRequest) {
	if req.AmfUeNgapID == nil || req.RanUeNgapID == nil {
		writeError(w, http.StatusBadRequest, "amf_ue_ngap_id and ran_ue_ngap_id are required")
		return
	}

	if len(req.PDUSessions) == 0 {
		writeError(w, http.StatusBadRequest, "pdu_sessions is required for path_switch_request")
		return
	}

	var sessions []ngap.PathSwitchSession

	for _, ps := range req.PDUSessions {
		dlIP := ps.DLIP
		if dlIP == "" {
			dlIP = "127.0.0.1"
		}

		teid := ps.DLTeid
		if teid == 0 {
			teid = 1
		}

		var rawTransfer []byte

		if ps.RawTransfer != nil {
			decoded, err := hex.DecodeString(*ps.RawTransfer)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_transfer: %v", err))
				return
			}

			rawTransfer = decoded
		}

		sessions = append(sessions, ngap.PathSwitchSession{PDUSessionID: ps.ID, DLTeid: teid, DLIP: dlIP, RawTransfer: rawTransfer})
	}

	secCaps, err := pathSwitchSecurityCapabilities(req.UESecurityCapabilities)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	encoded, err := ngap.BuildPathSwitchRequest(*req.RanUeNgapID, *req.AmfUeNgapID, gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, secCaps, sessions, req.FailedPDUSessions, req.OmitIEs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PathSwitchRequest: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	if len(req.WaitFor) == 0 {
		writeJSON(w, http.StatusOK, SendNGAPResponse{})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.WaitFor, err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func pathSwitchSecurityCapabilities(in *UESecurityCapabilitiesInput) (ngap.UESecurityCapabilities, error) {
	parse := func(name, s string, def []byte) ([]byte, error) {
		if s == "" {
			return def, nil
		}

		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("decode %s security capability %q: %w", name, s, err)
		}

		if len(b) != 2 {
			return nil, fmt.Errorf("%s security capability must be 2 bytes, got %d", name, len(b))
		}

		return b, nil
	}

	var (
		caps ngap.UESecurityCapabilities
		err  error
	)

	if in == nil {
		in = &UESecurityCapabilitiesInput{}
	}

	if caps.NREncryption, err = parse("nr_encryption", in.NREncryption, []byte{0xe0, 0x00}); err != nil {
		return caps, err
	}

	if caps.NRIntegrity, err = parse("nr_integrity", in.NRIntegrity, []byte{0xe0, 0x00}); err != nil {
		return caps, err
	}

	if caps.EUTRAEncryption, err = parse("eutra_encryption", in.EUTRAEncryption, []byte{0x00, 0x00}); err != nil {
		return caps, err
	}

	if caps.EUTRAIntegrity, err = parse("eutra_integrity", in.EUTRAIntegrity, []byte{0x00, 0x00}); err != nil {
		return caps, err
	}

	return caps, nil
}

func handleHandoverFailure(w http.ResponseWriter, t *transport.NGAPTransport, req *SendGnBNGAPRequest) {
	if req.AmfUeNgapID == nil {
		writeError(w, http.StatusBadRequest, "amf_ue_ngap_id is required for handover_failure")
		return
	}

	cause := ngap.CauseRadioNetworkHoFailureInTarget
	if req.Cause != nil {
		cause = *req.Cause
	}

	encoded, err := ngap.BuildHandoverFailure(*req.AmfUeNgapID, cause)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverFailure: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func handleRawNGAP(w http.ResponseWriter, r *http.Request, t *transport.NGAPTransport, req *SendGnBNGAPRequest) {
	pdu, err := hex.DecodeString(*req.RawNGAPPDU)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_ngap_pdu: %v", err))
		return
	}

	if err := t.Send(pdu, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	if len(req.WaitFor) == 0 {
		writeJSON(w, http.StatusOK, SendNGAPResponse{})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.WaitFor, err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func handleNGReset(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, t *transport.NGAPTransport, req *SendGnBNGAPRequest) {
	var connections []ngap.NGResetConnection

	for _, ueID := range req.ResetUEIDs {
		ue, ok := gnb.GetUE(ueID)
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
			return
		}

		amf := ue.AmfUeNgapID
		ran := ue.RanUeNgapID
		connections = append(connections, ngap.NGResetConnection{AmfUeNgapID: &amf, RanUeNgapID: &ran})
	}

	encoded, err := ngap.BuildNGReset(connections)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build NGReset: %v", err))
		return
	}

	if err := t.Send(encoded, true); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, "NGResetAcknowledge", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for NGResetAcknowledge: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
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

func securityOpts(req *SendNGAPRequest) []nasCodec.EncodeOption {
	var opts []nasCodec.EncodeOption
	if req.CorruptMAC {
		opts = append(opts, nasCodec.WithCorruptMAC())
	}

	if req.NASCountOverride != nil {
		opts = append(opts, nasCodec.WithNASCountOverride(*req.NASCountOverride))
	}

	return opts
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

func handleRegistrationRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	if req.RawNASPDU != nil {
		nasPDU, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		if req.ExistingConnection {
			sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
			return
		}

		ngapMsg, err := ngap.BuildInitialUEMessageFromState(
			ue.RanUeNgapID, nasPDU,
			gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, nil, initialUEOverrides(req),
		)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("build initial ue message: %v", err))
			return
		}

		sendAndWait(w, r, gnb, ue, t, req, ngapMsg, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")

		return
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
		Overrides:        req,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build NAS RegistrationRequest: %v", err))
		return
	}

	if secured {
		nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, nasPDU, gonas.SecurityHeaderTypeIntegrityProtected, securityOpts(req)...)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	if req.ExistingConnection {
		sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
		return
	}

	ngapMsg, err := ngap.BuildInitialUEMessageFromState(
		ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, nil, initialUEOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("build initial ue message: %v", err))
		return
	}

	sendAndWait(w, r, gnb, ue, t, req, ngapMsg, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")
}

func handleAuthenticationResponse(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		var resStar []byte

		if req.ResStarOverride != nil {
			var err error

			resStar, err = hex.DecodeString(*req.ResStarOverride)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("decode res_star_override: %v", err))
				return
			}
		} else if len(ue.LastRAND) == 0 || len(ue.LastAUTN) == 0 {
			resStar = make([]byte, 16)
		} else {
			akaResult, err := crypto.ComputeResStar(ue.K, ue.OPc, ue.Sqn, ue.Supi, ue.Snn, ue.LastRAND, ue.LastAUTN)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("5G-AKA: %v", err))
				return
			}

			ue.Kamf = akaResult.Kamf
			resStar = akaResult.RESstar
		}

		var err error

		nasPDU, err = nasCodec.BuildAuthenticationResponse(resStar)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build AuthenticationResponse: %v", err))
			return
		}
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
}

func handleSecurityModeComplete(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
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
			Overrides:        req,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build inner RegistrationRequest: %v", err))
			return
		}

		smcPDU, err := nasCodec.BuildSecurityModeComplete(regReqPDU, ue.IMEISV)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build SecurityModeComplete: %v", err))
			return
		}

		nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, smcPDU,
			gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, securityOpts(req)...)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "InitialContextSetupRequest", "DownlinkNASTransport", "ErrorIndication")
}

func handleRegistrationComplete(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	icsResp, err := ngap.BuildInitialContextSetupResponse(ue.AmfUeNgapID, ue.RanUeNgapID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build InitialContextSetupResponse: %v", err))
		return
	}

	if err := t.Send(icsResp, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send InitialContextSetupResponse: %v", err))
		return
	}

	var nasPDU []byte

	if req.RawNASPDU != nil {
		nasPDU, err = hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}
	} else {
		regCompletePDU, err := nasCodec.BuildRegistrationComplete()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build RegistrationComplete: %v", err))
			return
		}

		nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, regCompletePDU,
			gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication", "UEContextReleaseCommand")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}

	return ""
}

func captureTunnel(gnb *store.GNBContext, ue *store.UEContext, pduSessionID int64, dlTeid uint32, ngapResp *ngap.NGAPResponse, nasResp *nasCodec.NASResponse) {
	info := &store.PDUSessionInfo{
		PDUSessionID: pduSessionID,
		N3GnbIP:      gnb.N3Addr,
		DLTeid:       dlTeid,
		QFI:          1,
	}

	gnbN3IsV6 := false
	if a, err := netip.ParseAddr(gnb.N3Addr); err == nil {
		gnbN3IsV6 = a.Is6()
	}

	for _, ie := range ngapResp.IEs {
		for _, item := range ie.PDUSessionSetupItems {
			if item.PDUSessionID == pduSessionID {
				info.ULTeid = item.ULTeid
				if gnbN3IsV6 {
					info.UPFIP = firstNonEmpty(item.UPFN3IPv6, item.UPFN3IP)
				} else {
					info.UPFIP = firstNonEmpty(item.UPFN3IP, item.UPFN3IPv6)
				}
			}
		}
	}

	if nasResp != nil {
		info.UEIP = nasResp.PDUAddress
	}

	gnb.StorePDUSession(ue.RanUeNgapID, info)
}

func handlePDUSessionEstablishmentRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, gt *gtpu.Endpoint, req *SendNGAPRequest) {
	pduSessionID := ue.PDUSessionID
	if req.PDUSessionIDOverride != nil {
		pduSessionID = *req.PDUSessionIDOverride
	}

	if pduSessionID == 0 {
		pduSessionID = 1
	}

	pduSessionType := ue.PDUSessionType
	if pduSessionType == 0 {
		pduSessionType = 1
	}

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		sendUplinkAndWait(w, r, gnb, ue, t, req, raw, "PDUSessionResourceSetupRequest", "DownlinkNASTransport", "ErrorIndication")

		return
	}

	var (
		pduReq []byte
		err    error
	)

	if req.InnerSMPayload != nil {
		pduReq, err = hex.DecodeString(*req.InnerSMPayload)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode inner_sm_payload: %v", err))
			return
		}
	} else {
		pduReq, err = nasCodec.BuildPDUSessionEstablishmentRequest(&nasCodec.PDUSessionEstablishmentRequestOpts{
			PDUSessionID:   pduSessionID,
			PDUSessionType: pduSessionType,
			PTI:            ptiFor(req),
			AlwaysOn:       req.AlwaysOnRequested != nil && *req.AlwaysOnRequested,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionEstablishmentRequest: %v", err))
			return
		}
	}

	ulNas, err := nasCodec.BuildULNASTransport(pduSessionID, pduReq, ue.DNN, ue.SST, ue.SD)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	securedPDU, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas,
		gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, securedPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"PDUSessionResourceSetupRequest", "DownlinkNASTransport", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for PDU establishment response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		if ie.NasPDU != nil {
			nasPDUBytes, err := hex.DecodeString(*ie.NasPDU)
			if err != nil {
				continue
			}

			nasResp, _ = nasCodec.DecodeSecuredNAS(ue, nasPDUBytes)
		}
	}

	if ngapResp.MessageType == "PDUSessionResourceSetupRequest" {
		dlTeid := uint32(ue.RanUeNgapID)<<8 | uint32(pduSessionID)

		pduSetupResp, err := ngap.BuildPDUSessionResourceSetupResponse(
			ue.AmfUeNgapID, ue.RanUeNgapID, int64(pduSessionID), dlTeid, gnb.N3Addr)
		if err == nil {
			_ = t.Send(pduSetupResp, false)
		}

		if gt != nil {
			captureTunnel(gnb, ue, int64(pduSessionID), dlTeid, ngapResp, nasResp)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
}

func handleDeregistrationRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
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
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build DeregistrationRequest: %v", err))
			return
		}

		nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, deregPDU,
			gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"UEContextReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		if ie.NasPDU != nil {
			nasPDUBytes, err := hex.DecodeString(*ie.NasPDU)
			if err != nil {
				continue
			}

			nasResp, _ = nasCodec.DecodeSecuredNAS(ue, nasPDUBytes)
		}
	}

	if ngapResp.MessageType == "UEContextReleaseCommand" {
		releaseComplete, err := ngap.BuildUEContextReleaseComplete(ue.AmfUeNgapID, ue.RanUeNgapID)
		if err == nil {
			_ = t.Send(releaseComplete, false)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
}

func handleUEContextReleaseRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build UEContextReleaseRequest: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"UEContextReleaseCommand", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for response: %v", err))
		return
	}

	if ngapResp.MessageType == "UEContextReleaseCommand" {
		releaseComplete, err := ngap.BuildUEContextReleaseComplete(ue.AmfUeNgapID, ue.RanUeNgapID)
		if err == nil {
			_ = t.Send(releaseComplete, false)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func handleIdentityResponse(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		mobileIdentity := ue.Suci.Buffer
		if req.MobileIdentityOverride != nil {
			b, err := hex.DecodeString(*req.MobileIdentityOverride)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("decode mobile_identity_override: %v", err))
				return
			}

			mobileIdentity = b
		}

		idPDU, err := nasCodec.BuildIdentityResponse(mobileIdentity)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build IdentityResponse: %v", err))
			return
		}

		nasPDU = idPDU

		if len(ue.Kamf) > 0 {
			nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, idPDU, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
				return
			}
		}
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")
}

func ptiFor(req *SendNGAPRequest) uint8 {
	if req != nil && req.PTIOverride != nil {
		return *req.PTIOverride
	}

	return 0x01
}

func pduSessionIDForRelease(ue *store.UEContext) uint8 {
	if ue.PDUSessionID >= 1 && ue.PDUSessionID <= 15 {
		return ue.PDUSessionID
	}

	return 1
}

func handlePDUSessionReleaseRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		relReq, err := nasCodec.BuildPDUSessionReleaseRequest(pduSessionID, ptiFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionReleaseRequest: %v", err))
			return
		}

		inner = relReq
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, secured, "PDUSessionResourceReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
}

func handlePDUSessionModificationRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		modReq, err := nasCodec.BuildPDUSessionModificationRequest(pduSessionID, ptiFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionModificationRequest: %v", err))
			return
		}

		inner = modReq
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, secured, "PDUSessionResourceModifyRequest", "DownlinkNASTransport", "ErrorIndication")
}

func handlePDUSessionReleaseComplete(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		cmp, err := nasCodec.BuildPDUSessionReleaseComplete(pduSessionID, ptiFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionReleaseComplete: %v", err))
			return
		}

		inner = cmp
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, secured,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func handlePDUSessionModificationComplete(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		cmp, err := nasCodec.BuildPDUSessionModificationComplete(pduSessionID, ptiFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionModificationComplete: %v", err))
			return
		}

		inner = cmp
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, secured,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func cause5GSMFor(req *SendNGAPRequest) uint8 {
	if req != nil && req.Cause5GSMOverride != nil {
		return *req.Cause5GSMOverride
	}

	return nasMessage.Cause5GSMProtocolErrorUnspecified
}

func sendInner5GSM(w http.ResponseWriter, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest, inner []byte) {
	pduSessionID := pduSessionIDForRelease(ue)

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, secured,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func handlePDUSessionModificationCommandReject(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		rej, err := nasCodec.BuildPDUSessionModificationCommandReject(pduSessionID, ptiFor(req), cause5GSMFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionModificationCommandReject: %v", err))
			return
		}

		inner = rej
	}

	sendInner5GSM(w, gnb, ue, t, req, inner)
}

func handleStatus5GSM(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		st, err := nasCodec.BuildPDUSessionStatus5GSM(pduSessionID, ptiFor(req), cause5GSMFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build Status5GSM: %v", err))
			return
		}

		inner = st
	}

	sendInner5GSM(w, gnb, ue, t, req, inner)
}

func handleAuthenticationFailure(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
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
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("compute AUTS: %v", err))
				return
			}

			auts = a
		}

		pdu, err := nasCodec.BuildAuthenticationFailure(cause, auts)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build AuthenticationFailure: %v", err))
			return
		}

		nasPDU = pdu
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
}

func handleSecurityModeReject(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		cause := uint8(nasMessage.Cause5GMMUESecurityCapabilitiesMismatch)
		if req.Cause5GMM != nil {
			cause = *req.Cause5GMM
		}

		pdu, err := nasCodec.BuildSecurityModeReject(cause)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build SecurityModeReject: %v", err))
			return
		}

		nasPDU = pdu
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "UEContextReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
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

func handleServiceRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	ue.RanUeNgapID = gnb.AllocateRanUeNgapID()

	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		serviceType := nasMessage.ServiceTypeData
		if req.ServiceType != nil {
			serviceType = *req.ServiceType
		}

		status, err := serviceRequestPDUStatus(ue, req)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode pdu_session_status: %v", err))
			return
		}

		srPDU, err := nasCodec.BuildServiceRequest(&nasCodec.ServiceRequestOpts{
			ServiceType:      serviceType,
			NgKsi:            ue.NgKsi,
			Guti:             ue.Guti,
			PDUSessionStatus: status,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ServiceRequest: %v", err))
			return
		}

		if len(ue.Kamf) > 0 {
			nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, srPDU, gonas.SecurityHeaderTypeIntegrityProtected, securityOpts(req)...)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
				return
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

	ngapMsg, err := ngap.BuildInitialUEMessageFromState(
		ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, fiveGSTMSIFromGUTI(ue.Guti), overrides,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("build initial ue message: %v", err))
		return
	}

	encoded, err := ngap.Encode(ngapMsg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"InitialContextSetupRequest", "DownlinkNASTransport", "PDUSessionResourceSetupRequest", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for service request response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

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

			nasResp, _ = nasCodec.DecodeSecuredNAS(ue, nasPDUBytes)
		}
	}

	if ngapResp.MessageType == "InitialContextSetupRequest" {
		icsResp, berr := ngap.BuildInitialContextSetupResponse(ue.AmfUeNgapID, ue.RanUeNgapID)
		if berr == nil {
			_ = t.Send(icsResp, false)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
}

func handleInjectNAS(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	switch {
	case req.ReplayLast:
		if len(ue.LastUplinkNAS) == 0 {
			writeError(w, http.StatusBadRequest, "no prior uplink to replay")
			return
		}

		nasPDU = ue.LastUplinkNAS
	case req.RawNASPDU != nil:
		decoded, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("raw_nas_pdu must be hex: %v", err))
			return
		}

		nasPDU = decoded
	default:
		writeError(w, http.StatusBadRequest, "inject_nas requires raw_nas_pdu or replay_last")
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build UplinkNASTransport: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, "DownlinkNASTransport", "ErrorIndication", "UEContextReleaseCommand")
	if err != nil {
		writeJSON(w, http.StatusOK, SendNGAPResponse{})
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func handleUECapabilityInfo(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	radioCap := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	if req.UERadioCapability != nil {
		decoded, err := hex.DecodeString(*req.UERadioCapability)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("ue_radio_capability must be hex: %v", err))
			return
		}

		radioCap = decoded
	}

	encoded, err := ngap.BuildUERadioCapabilityInfoIndication(effectiveAmfID(req, ue), effectiveRanID(req, ue), radioCap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build UERadioCapabilityInfoIndication: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)), "ErrorIndication")
	if err != nil {
		writeJSON(w, http.StatusOK, SendNGAPResponse{})
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func handleErrorIndication(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	encoded, err := ngap.BuildErrorIndication(effectiveAmfID(req, ue), effectiveRanID(req, ue), causeRadioNetworkUnspecified)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ErrorIndication: %v", err))
		return
	}

	sendRawAndWait(w, r, gnb, ue, t, req, encoded, "UEContextReleaseCommand", "ErrorIndication")
}

func sendAndWait(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest, ngapMsg *ngap.NGAPMessage, waitFor ...string) {
	encoded, err := ngap.Encode(ngapMsg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	sendRawAndWait(w, r, gnb, ue, t, req, encoded, waitFor...)
}

func sendUplinkAndWait(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest, nasPDU []byte, waitFor ...string) {
	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	sendRawAndWait(w, r, gnb, ue, t, req, encoded, waitFor...)
}

func sendRawAndWait(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest, encoded []byte, waitFor ...string) {
	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)), waitFor...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		// An Error Indication echoes the AP IDs it was sent; it assigns none.
		if ie.AmfUeNgapID != nil && ngapResp.MessageType != "ErrorIndication" {
			ue.AmfUeNgapID = *ie.AmfUeNgapID
		}

		if ie.NasPDU != nil {
			nasPDUBytes, err := hex.DecodeString(*ie.NasPDU)
			if err != nil {
				continue
			}

			if len(ue.Kamf) > 0 {
				nasResp, _ = nasCodec.DecodeSecuredNAS(ue, nasPDUBytes)
			} else {
				nasResp, _ = nasCodec.Decode(nasPDUBytes)
			}

			if nasResp != nil && nasResp.RAND != "" {
				randBytes, _ := hex.DecodeString(nasResp.RAND)
				autnBytes, _ := hex.DecodeString(nasResp.AUTN)
				ue.LastRAND = randBytes
				ue.LastAUTN = autnBytes
			}

			if nasResp != nil && nasResp.NgKSI != nil && nasResp.SelectedCipheringAlg != nil {
				ue.NgKsi = uint8(*nasResp.NgKSI)
			}

			if nasResp != nil && nasResp.GUTI != "" {
				gutiBytes, err := hex.DecodeString(nasResp.GUTI)
				if err == nil {
					ue.Guti = nasCodec.ParseGUTI(gutiBytes)
				}
			}
		}
	}

	if ngapResp.MessageType == "InitialContextSetupRequest" {
		if icsResp, berr := ngap.BuildInitialContextSetupResponse(ue.AmfUeNgapID, ue.RanUeNgapID); berr == nil {
			_ = t.Send(icsResp, false)
		}
	}

	if ngapResp.MessageType == "PDUSessionResourceReleaseCommand" {
		if relResp, berr := ngap.BuildPDUSessionResourceReleaseResponse(ue.AmfUeNgapID, ue.RanUeNgapID); berr == nil {
			_ = t.Send(relResp, false)
		}
	}

	if ngapResp.MessageType == "UEContextReleaseCommand" {
		if relComplete, berr := ngap.BuildUEContextReleaseComplete(ue.AmfUeNgapID, ue.RanUeNgapID); berr == nil {
			_ = t.Send(relComplete, false)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
}
