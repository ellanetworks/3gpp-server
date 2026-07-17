// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

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
