// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

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
		resp, herr = handleENBUECapabilityInfo(ctx, enb, ue, t, &req)
	case "handover_required":
		resp, herr = handleENBHandoverRequired(h.Store, ue, t, &req)
	case "handover_cancel":
		resp, herr = handleENBHandoverCancel(ctx, ue, t, &req)
	case "enb_status_transfer":
		resp, herr = handleENBENBStatusTransfer(ue, t, &req)
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

// waitDownlinkReq matches by the effective (override-aware) AP IDs, so an ERROR
// INDICATION echoing the AP IDs a forged uplink carried (TS 36.413 §10.6) is
// recognised. Without an override it behaves like waitDownlink.
func waitDownlinkReq(ctx context.Context, t *transport.S1APTransport, ue *store.UEEPSContext, req *SendENBUES1APRequest, types ...string) (*s1ap.S1APResponse, error) {
	mmeID, enbID := forgeIDs(ue, req)

	match := func(r *s1ap.S1APResponse) bool {
		if r.ENBUES1APID != nil && *r.ENBUES1APID == int64(enbID) {
			return true
		}

		return r.MMEUES1APID != nil && mmeID != 0 && *r.MMEUES1APID == int64(mmeID)
	}

	return t.WaitForMessageMatching(ctx, match, types...)
}

func waitDownlinkTolerantReq(ctx context.Context, t *transport.S1APTransport, ue *store.UEEPSContext, req *SendENBUES1APRequest, types ...string) *s1ap.S1APResponse {
	resp, err := waitDownlinkReq(ctx, t, ue, req, types...)
	if err != nil {
		return nil
	}

	return resp
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
