// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

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

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	var (
		resp *SendENBUES1APResponse
		herr error
	)

	switch {
	case req.RawS1APPDU != nil:
		resp, herr = handleENBRawS1AP(ctx, t, &req)
	case req.MessageType == "reset":
		resp, herr = handleENBReset(ctx, enb, t, &req)
	case req.MessageType == "path_switch_request":
		resp, herr = handleENBPathSwitchRequest(ctx, enb, t, &req)
	case req.MessageType == "handover_request_acknowledge":
		resp, herr = handleENBHandoverRequestAcknowledge(enb, t, &req)
	case req.MessageType == "handover_notify":
		resp, herr = handleENBHandoverNotify(enb, t, &req)
	case req.MessageType == "handover_failure":
		resp, herr = handleENBHandoverFailure(t, &req)
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

// Reset is non-UE-associated: it resets the whole S1 interface, or the UE
// associations named in reset_ue_ids (TS 36.413 §8.7.1).
func handleENBReset(ctx context.Context, enb *store.ENBContext, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBUES1APResponse, error) {
	var connections []s1ap.ResetConnection

	for _, ueID := range req.ResetUEIDs {
		ue, ok := enb.GetUE(ueID)
		if !ok {
			return nil, httpErrorf(http.StatusNotFound, "ue %s not found", ueID)
		}

		mme := ue.MMEUES1APID
		enbID := ue.ENBUES1APID
		connections = append(connections, s1ap.ResetConnection{MMEUES1APID: &mme, ENBUES1APID: &enbID})
	}

	pdu, err := s1ap.BuildReset(len(connections) == 0, connections)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build Reset: %v", err)
	}

	if err := t.Send(pdu, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	resp, err := t.WaitForMessage(ctx, "ResetAcknowledge", "ErrorIndication")
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for ResetAcknowledge: %v", err)
	}

	return &SendENBUES1APResponse{S1AP: resp}, nil
}

func handleENBRawS1AP(ctx context.Context, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBUES1APResponse, error) {
	pdu, err := hex.DecodeString(*req.RawS1APPDU)
	if err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "decode raw_s1ap_pdu: %v", err)
	}

	if err := t.Send(pdu, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	if len(req.WaitFor) == 0 {
		return &SendENBUES1APResponse{}, nil
	}

	resp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for %v: %v", req.WaitFor, err)
	}

	return &SendENBUES1APResponse{S1AP: resp}, nil
}

func handleENBPathSwitchRequest(ctx context.Context, enb *store.ENBContext, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBUES1APResponse, error) {
	if req.MMEUES1APID == nil || req.ENBUES1APID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "mme_ue_s1ap_id and enb_ue_s1ap_id are required")
	}

	if len(req.ERABs) == 0 {
		return nil, httpErrorf(http.StatusBadRequest, "erabs is required for path_switch_request")
	}

	erab := req.ERABs[0]

	teid := erab.DLTeid
	if teid == 0 {
		teid = *req.ENBUES1APID + 0x1000
	}

	// The S1AP encoding drops the EEA0/EIA0 bit, so shift the octets left.
	netcap := naseps.DefaultUENetworkCapability

	encoded, err := s1ap.BuildPathSwitchRequest(s1ap.PathSwitchRequestParams{
		ENBUES1APID:                   *req.ENBUES1APID,
		SourceMMEUES1APID:             *req.MMEUES1APID,
		ERABID:                        erab.ID,
		TargetS1UAddr:                 enb.N3Addr,
		TargetTEID:                    teid,
		MCC:                           enb.MCC,
		MNC:                           enb.MNC,
		TAC:                           enb.TAC,
		CellID:                        1,
		EncryptionAlgorithms:          uint16(netcap[0]<<1) << 8,
		IntegrityProtectionAlgorithms: uint16(netcap[1]<<1) << 8,
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build PathSwitchRequest: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	if len(req.WaitFor) == 0 {
		return &SendENBUES1APResponse{}, nil
	}

	resp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for %v: %v", req.WaitFor, err)
	}

	return &SendENBUES1APResponse{S1AP: resp}, nil
}

func handleENBHandoverRequestAcknowledge(enb *store.ENBContext, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBUES1APResponse, error) {
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

	return &SendENBUES1APResponse{}, nil
}

func handleENBHandoverNotify(enb *store.ENBContext, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBUES1APResponse, error) {
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

	return &SendENBUES1APResponse{}, nil
}

func handleENBHandoverFailure(t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBUES1APResponse, error) {
	if req.MMEUES1APID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "mme_ue_s1ap_id is required for handover_failure")
	}

	cause := s1ap.CauseRadioNetworkHOFailureInTarget
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

	return &SendENBUES1APResponse{}, nil
}

func handleENBHandoverRequired(st *store.Store, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if req.TargetENBID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "target_enb_id is required for handover_required")
	}

	target, err := st.GetENB(*req.TargetENBID)
	if err != nil {
		return nil, httpErrorf(http.StatusNotFound, "target enb not found: %v", err)
	}

	encoded, err := s1ap.BuildHandoverRequired(s1ap.HandoverRequiredParams{
		MMEUES1APID: sourceMMEID(ue, req),
		ENBUES1APID: sourceENBID(ue, req),
		Cause:       handoverRequiredCause(req),
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

	return &SendENBUES1APResponse{}, nil
}

func handleENBHandoverCancel(ctx context.Context, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	cause := s1ap.CauseRadioNetworkHandoverCancelled
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

	return &SendENBUES1APResponse{S1AP: resp}, nil
}

func handleENBEnbStatusTransfer(ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
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

	return &SendENBUES1APResponse{}, nil
}

func handoverRequiredCause(req *SendENBUES1APRequest) int {
	if req != nil && req.HandoverRequiredCause != nil {
		return *req.HandoverRequiredCause
	}

	return s1ap.CauseRadioNetworkHandoverDesirableForRadioReason
}

func sourceMMEID(ue *store.UEEPSContext, req *SendENBUES1APRequest) uint32 {
	if req.MMEUES1APIDOverride != nil {
		return *req.MMEUES1APIDOverride
	}

	return ue.MMEUES1APID
}

func sourceENBID(ue *store.UEEPSContext, req *SendENBUES1APRequest) uint32 {
	if req.ENBUES1APIDOverride != nil {
		return *req.ENBUES1APIDOverride
	}

	return ue.ENBUES1APID
}

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

	src.MigrateUE(target, ue, req.MMEUES1APID, req.ENBUES1APID)

	writeJSON(w, http.StatusOK, MigrateENBUEResponse{
		UEID:        ue.ID,
		ENBID:       req.TargetENBID,
		MMEUES1APID: ue.MMEUES1APID,
		ENBUES1APID: ue.ENBUES1APID,
	})
}
