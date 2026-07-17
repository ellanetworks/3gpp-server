// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	nasCodec "github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}

	return ""
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
