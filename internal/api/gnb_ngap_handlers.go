// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

func (h *Handler) SendGNBUENGAP(w http.ResponseWriter, r *http.Request) {
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

	var req SendGNBUENGAPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	var (
		resp *SendGNBUENGAPResponse
		herr error
	)

	switch req.MessageType {
	case "registration_request":
		resp, herr = handleGNBRegistrationRequest(ctx, gnb, ue, t, &req)
	case "authentication_response":
		resp, herr = handleGNBAuthenticationResponse(ctx, gnb, ue, t, &req)
	case "security_mode_complete":
		resp, herr = handleGNBSecurityModeComplete(ctx, gnb, ue, t, &req)
	case "registration_complete":
		resp, herr = handleGNBRegistrationComplete(ctx, gnb, ue, t, &req)
	case "pdu_session_establishment_request":
		resp, herr = handleGNBPDUSessionEstablishmentRequest(ctx, gnb, ue, t, h.GTPU[gnbID], &req)
	case "deregistration_request":
		resp, herr = handleGNBDeregistrationRequest(ctx, gnb, ue, t, &req)
	case "ue_context_release_request":
		resp, herr = handleGNBUEContextReleaseRequest(ctx, ue, t, &req)
	case "service_request":
		resp, herr = handleGNBServiceRequest(ctx, gnb, ue, t, &req)
	case "inject_nas":
		resp, herr = handleGNBInjectNAS(ctx, gnb, ue, t, &req)
	case "error_indication":
		resp, herr = handleGNBErrorIndication(ctx, ue, t, &req)
	case "ue_capability_info":
		resp, herr = handleGNBUECapabilityInfo(ctx, ue, t, &req)
	case "identity_response":
		resp, herr = handleGNBIdentityResponse(ctx, gnb, ue, t, &req)
	case "pdu_session_release_request":
		resp, herr = handleGNBPDUSessionReleaseRequest(ctx, gnb, ue, t, &req)
	case "pdu_session_modification_request":
		resp, herr = handleGNBPDUSessionModificationRequest(ctx, gnb, ue, t, &req)
	case "pdu_session_release_complete":
		resp, herr = handleGNBPDUSessionReleaseComplete(gnb, ue, t, &req)
	case "pdu_session_modification_complete":
		resp, herr = handleGNBPDUSessionModificationComplete(gnb, ue, t, &req)
	case "pdu_session_modification_command_reject":
		resp, herr = handleGNBPDUSessionModificationCommandReject(gnb, ue, t, &req)
	case "status_5gsm":
		resp, herr = handleGNBStatus5GSM(gnb, ue, t, &req)
	case "authentication_failure":
		resp, herr = handleGNBAuthenticationFailure(ctx, gnb, ue, t, &req)
	case "security_mode_reject":
		resp, herr = handleGNBSecurityModeReject(ctx, gnb, ue, t, &req)
	case "handover_required":
		resp, herr = handleGNBHandoverRequired(gnb, ue, t, &req)
	case "ran_status_transfer":
		resp, herr = handleGNBRANStatusTransfer(ue, t, &req)
	case "handover_cancel":
		resp, herr = handleGNBHandoverCancel(ctx, ue, t, &req)
	case "initial_context_setup_failure":
		resp, herr = handleGNBInitialContextSetupFailure(ue, t, &req)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported message_type: %s", req.MessageType))
		return
	}

	if herr != nil {
		writeError(w, statusForError(herr), herr.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) SendGNBNGAP(w http.ResponseWriter, r *http.Request) {
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

	var req SendGNBNGAPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	var (
		resp *SendGNBUENGAPResponse
		herr error
	)

	switch {
	case req.RawNGAPPDU != nil:
		resp, herr = handleGNBRawNGAP(ctx, t, &req)
	case req.MessageType == "ng_reset":
		resp, herr = handleGNBNGReset(ctx, gnb, t, &req)
	case req.MessageType == "handover_request_acknowledge":
		resp, herr = handleGNBHandoverRequestAcknowledge(t, &req)
	case req.MessageType == "handover_failure":
		resp, herr = handleGNBHandoverFailure(t, &req)
	case req.MessageType == "handover_notify":
		resp, herr = handleGNBHandoverNotify(gnb, t, &req)
	case req.MessageType == "path_switch_request":
		resp, herr = handleGNBPathSwitchRequest(ctx, gnb, t, &req)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported message_type: %s", req.MessageType))
		return
	}

	if herr != nil {
		writeError(w, statusForError(herr), herr.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func effectiveRanID(req *SendGNBUENGAPRequest, ue *store.UEContext) int64 {
	if req != nil && req.RANUENGAPIDOverride != nil {
		return *req.RANUENGAPIDOverride
	}

	return ue.RANUENGAPID
}

func effectiveAmfID(req *SendGNBUENGAPRequest, ue *store.UEContext) int64 {
	if req != nil && req.AMFUENGAPIDOverride != nil {
		return *req.AMFUENGAPIDOverride
	}

	return ue.AMFUENGAPID
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}

	return ""
}

func sendAndWait(ctx context.Context, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest, ngapMsg *ngap.NGAPMessage, waitFor ...string) (*SendGNBUENGAPResponse, error) {
	encoded, err := ngap.Encode(ngapMsg)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	return sendRawAndWait(ctx, ue, t, req, encoded, waitFor...)
}

func sendUplinkAndWait(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest, nasPDU []byte, waitFor ...string) (*SendGNBUENGAPResponse, error) {
	encoded, err := ngap.BuildUplinkNASTransport(ngap.UplinkNASTransportParams{
		AMFUENGAPID: ue.AMFUENGAPID,
		RANUENGAPID: ue.RANUENGAPID,
		NASPDU:      nasPDU,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GNBID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	return sendRawAndWait(ctx, ue, t, req, encoded, waitFor...)
}

func sendRawAndWait(ctx context.Context, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest, encoded []byte, waitFor ...string) (*SendGNBUENGAPResponse, error) {
	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)), waitFor...)
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for response: %v", err)
	}

	var nasResp *nas.NASResponse

	var macVerified *bool

	// An Error Indication echoes the AP IDs it was sent; it assigns none.
	if ngapResp.AMFUENGAPID != nil && ngapResp.MessageType != "ErrorIndication" {
		ue.AMFUENGAPID = *ngapResp.AMFUENGAPID
	}

	if ngapResp.NasPDU != nil {
		if nasPDUBytes, err := hex.DecodeString(*ngapResp.NasPDU); err == nil {
			if len(ue.Kamf) > 0 {
				nasResp, macVerified = decodeGNBDownlinkNAS(ue, nasPDUBytes)
			} else {
				nasResp, _ = nas.Decode(nasPDUBytes)
			}

			if nasResp != nil && nasResp.RAND != "" {
				randBytes, _ := hex.DecodeString(nasResp.RAND)
				autnBytes, _ := hex.DecodeString(nasResp.AUTN)
				ue.RAND = randBytes
				ue.AUTN = autnBytes
			}

			if nasResp != nil && nasResp.NgKSI != nil && nasResp.SelectedCipheringAlgorithm != nil {
				ue.NgKsi = uint8(*nasResp.NgKSI)
			}

			if nasResp != nil && nasResp.GUTI != nil {
				ue.Guti = nas.GUTI5GFromStructured(nasResp.GUTI)
			}
		}
	}

	if ngapResp.MessageType == "InitialContextSetupRequest" {
		if icsResp, berr := ngap.BuildInitialContextSetupResponse(ue.AMFUENGAPID, ue.RANUENGAPID); berr == nil {
			_ = t.Send(icsResp, false)
		}
	}

	if ngapResp.MessageType == "PDUSessionResourceReleaseCommand" {
		if relResp, berr := ngap.BuildPDUSessionResourceReleaseResponse(ue.AMFUENGAPID, ue.RANUENGAPID); berr == nil {
			_ = t.Send(relResp, false)
		}
	}

	if ngapResp.MessageType == "UEContextReleaseCommand" {
		if relComplete, berr := ngap.BuildUEContextReleaseComplete(ue.AMFUENGAPID, ue.RANUENGAPID); berr == nil {
			_ = t.Send(relComplete, false)
		}
	}

	return &SendGNBUENGAPResponse{
		NGAP:        ngapResp,
		NAS:         nasResp,
		MACVerified: macVerified,
	}, nil
}
