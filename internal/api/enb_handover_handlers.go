// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

// SendENBS1AP drives a non-UE-associated S1AP message on the eNB's S1-MME
// association — the target-eNB side of S1 handover, addressing a UE the eNB does
// not own by the S1AP ID pair the MME assigned.
func (h *Handler) SendENBS1AP(w http.ResponseWriter, r *http.Request) {
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

	var req SendENBS1APRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// raw_s1ap_pdu bypasses message_type entirely.
	if req.RawS1APPDU != nil {
		h.handleRawS1AP(w, r, t, &req)
		return
	}

	var (
		resp *SendENBNASResponse
		herr error
	)

	switch req.MessageType {
	case "handover_request_acknowledge":
		resp, herr = h.handoverRequestAcknowledge(enb, t, &req)
	case "handover_notify":
		resp, herr = h.handoverNotify(enb, t, &req)
	case "handover_failure":
		resp, herr = h.handoverFailure(t, &req)
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

// handleRawS1AP writes a verbatim S1AP PDU onto the eNB's S1-MME association and
// optionally blocks for a downlink of one of req.WaitFor's types.
func (h *Handler) handleRawS1AP(w http.ResponseWriter, r *http.Request, t *transport.S1APTransport, req *SendENBS1APRequest) {
	pdu, err := hex.DecodeString(*req.RawS1APPDU)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_s1ap_pdu: %v", err))
		return
	}

	if err := t.Send(pdu, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	if len(req.WaitFor) == 0 {
		writeJSON(w, http.StatusOK, SendENBNASResponse{})
		return
	}

	timeout := 5 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	resp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.WaitFor, err))
		return
	}

	writeJSON(w, http.StatusOK, SendENBNASResponse{S1AP: resp})
}

func (h *Handler) handoverRequestAcknowledge(enb *store.ENBContext, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBNASResponse, error) {
	if req.MMEUES1APID == nil || req.ENBUES1APID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "mme_ue_s1ap_id and enb_ue_s1ap_id are required")
	}

	if len(req.Admitted) == 0 {
		return nil, httpErrorf(http.StatusBadRequest, "admitted_erabs is required for handover_request_acknowledge")
	}

	dlIP := enb.N3Addr
	if dlIP == "" {
		dlIP = "127.0.0.1"
	}

	admitted := make([]s1ap.HandoverAdmittedERAB, 0, len(req.Admitted))
	for _, e := range req.Admitted {
		ip := e.DLIP
		if ip == "" {
			ip = dlIP
		}

		teid := e.DLTeid
		if teid == 0 {
			teid = *req.ENBUES1APID + 0x1000
		}

		admitted = append(admitted, s1ap.HandoverAdmittedERAB{ERABID: e.ID, DLTeid: teid, DLAddr: ip})
	}

	encoded, err := s1ap.BuildHandoverRequestAcknowledge(s1ap.HandoverRequestAcknowledgeParams{
		MMEUES1APID:   *req.MMEUES1APID,
		ENBUES1APID:   *req.ENBUES1APID,
		Admitted:      admitted,
		FailedERABIDs: req.FailedERABs,
	})
	if err != nil {
		return nil, fmt.Errorf("build HandoverRequestAcknowledge: %w", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{}, nil
}

func (h *Handler) handoverNotify(enb *store.ENBContext, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBNASResponse, error) {
	if req.MMEUES1APID == nil || req.ENBUES1APID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "mme_ue_s1ap_id and enb_ue_s1ap_id are required")
	}

	cellID := uint32(1)
	if req.CellID != nil {
		cellID = *req.CellID
	}

	encoded, err := s1ap.BuildHandoverNotify(s1ap.HandoverNotifyParams{
		MMEUES1APID: *req.MMEUES1APID,
		ENBUES1APID: *req.ENBUES1APID,
		MCC:         enb.MCC,
		MNC:         enb.MNC,
		TAC:         enb.TAC,
		CellID:      cellID,
	})
	if err != nil {
		return nil, fmt.Errorf("build HandoverNotify: %w", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{}, nil
}

func (h *Handler) handoverFailure(t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBNASResponse, error) {
	if req.MMEUES1APID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "mme_ue_s1ap_id is required for handover_failure")
	}

	cause := s1ap.CauseHOFailureInTarget
	if req.Cause != nil {
		cause = *req.Cause
	}

	encoded, err := s1ap.BuildHandoverFailure(*req.MMEUES1APID, cause)
	if err != nil {
		return nil, fmt.Errorf("build HandoverFailure: %w", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{}, nil
}

func (h *Handler) handoverRequired(ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	if req.TargetENBID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "target_enb_id is required for handover_required")
	}

	target, err := h.Store.GetENB(*req.TargetENBID)
	if err != nil {
		return nil, httpErrorf(http.StatusNotFound, "target enb not found: %v", err)
	}

	encoded, err := s1ap.BuildHandoverRequired(s1ap.HandoverRequiredParams{
		MMEUES1APID: sourceMMEID(ue, req),
		ENBUES1APID: sourceENBID(ue, req),
		Cause:       s1ap.CauseHandoverDesirableForRadioReasons,
		TargetMCC:   target.MCC,
		TargetMNC:   target.MNC,
		TargetTAC:   target.TAC,
		TargetENBID: target.ENBID,
	})
	if err != nil {
		return nil, fmt.Errorf("build HandoverRequired: %w", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{}, nil
}

func (h *Handler) handoverCancel(ctx context.Context, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	cause := s1ap.CauseHandoverCancelled
	if req.HandoverCancelCause != nil {
		cause = *req.HandoverCancelCause
	}

	encoded, err := s1ap.BuildHandoverCancel(sourceMMEID(ue, req), sourceENBID(ue, req), cause)
	if err != nil {
		return nil, fmt.Errorf("build HandoverCancel: %w", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	resp, err := t.WaitForMessage(ctx, "HandoverCancelAcknowledge", "ErrorIndication")
	if err != nil {
		return nil, err
	}

	return &SendENBNASResponse{S1AP: resp}, nil
}

func (h *Handler) enbStatusTransfer(ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBNASRequest) (*SendENBNASResponse, error) {
	var container []byte

	if req.StatusTransferContainer != nil {
		decoded, err := hex.DecodeString(*req.StatusTransferContainer)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "status_transfer_container must be hex: %v", err)
		}

		container = decoded
	}

	encoded, err := s1ap.BuildENBStatusTransfer(sourceMMEID(ue, req), sourceENBID(ue, req), container)
	if err != nil {
		return nil, fmt.Errorf("build ENBStatusTransfer: %w", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	return &SendENBNASResponse{}, nil
}

// sourceMMEID and sourceENBID resolve the S1AP ID pair a source-eNB handover
// message carries: the request override when present, else the UE's stored IDs.
func sourceMMEID(ue *store.UEEPSContext, req *SendENBNASRequest) uint32 {
	if req.MMEUES1APIDOverride != nil {
		return *req.MMEUES1APIDOverride
	}

	return ue.MMEUES1APID
}

func sourceENBID(ue *store.UEEPSContext, req *SendENBNASRequest) uint32 {
	if req.ENBUES1APIDOverride != nil {
		return *req.ENBUES1APIDOverride
	}

	return ue.ENBUES1APID
}

// MigrateENBUE moves a UE context to the target eNB's association, modelling the
// UE arriving at the target after an S1 handover. The UE keeps its security
// context; its S1AP ID pair becomes the target's values.
func (h *Handler) MigrateENBUE(w http.ResponseWriter, r *http.Request) {
	src, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	ue, ok := src.GetUE(r.PathValue("ue_id"))
	if !ok {
		writeError(w, http.StatusNotFound, "ue not found")
		return
	}

	var req MigrateENBUERequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	target, err := h.Store.GetENB(req.TargetENBID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("target enb not found: %v", err))
		return
	}

	if req.MMEUES1APID != nil {
		ue.MMEUES1APID = *req.MMEUES1APID
	}

	if req.ENBUES1APID != nil {
		ue.ENBUES1APID = *req.ENBUES1APID
	}

	src.DeleteUE(ue.ID)
	target.AdoptUE(ue)

	writeJSON(w, http.StatusOK, map[string]any{
		"ue_id":          ue.ID,
		"enb_id":         req.TargetENBID,
		"mme_ue_s1ap_id": ue.MMEUES1APID,
		"enb_ue_s1ap_id": ue.ENBUES1APID,
	})
}
