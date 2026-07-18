// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

func handleGNBHandoverRequired(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
	if req.TargetGnbID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "target_gnb_id is required for handover_required")
	}

	pduSessionID := pduSessionIDForRelease(ue)

	amfUeNgapID := ue.AMFUENGAPID
	if req.AMFUENGAPIDOverride != nil {
		amfUeNgapID = *req.AMFUENGAPIDOverride
	}

	ranUeNgapID := ue.RANUENGAPID
	if req.RANUENGAPIDOverride != nil {
		ranUeNgapID = *req.RANUENGAPIDOverride
	}

	pduSessionIDs := []int64{int64(pduSessionID)}
	if len(req.PDUSessionIDs) > 0 {
		pduSessionIDs = req.PDUSessionIDs
	}

	cause := int64(ngap.CauseRadioNetworkHandoverDesirableForRadioReason)
	if req.HandoverRequiredCause != nil {
		cause = *req.HandoverRequiredCause
	}

	encoded, err := ngap.BuildHandoverRequired(ngap.HandoverRequiredParams{
		AMFUENGAPID:       amfUeNgapID,
		RANUENGAPID:       ranUeNgapID,
		TargetGnbID:       *req.TargetGnbID,
		MCC:               gnb.MCC,
		MNC:               gnb.MNC,
		TAC:               gnb.TAC,
		PDUSessionIDs:     pduSessionIDs,
		CauseRadioNetwork: cause,
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build HandoverRequired: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendGNBUENGAPResponse{}, nil
}

func handleGNBRANStatusTransfer(ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
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
		return nil, httpErrorf(http.StatusInternalServerError, "build UplinkRANStatusTransfer: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendGNBUENGAPResponse{}, nil
}

func handleGNBHandoverCancel(ctx context.Context, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
	amfUeNgapID := ue.AMFUENGAPID
	if req.AMFUENGAPIDOverride != nil {
		amfUeNgapID = *req.AMFUENGAPIDOverride
	}

	ranUeNgapID := ue.RANUENGAPID
	if req.RANUENGAPIDOverride != nil {
		ranUeNgapID = *req.RANUENGAPIDOverride
	}

	cause := ngap.CauseRadioNetworkHandoverCancelled
	if req.HandoverCancelCause != nil {
		cause = *req.HandoverCancelCause
	}

	encoded, err := ngap.BuildHandoverCancel(amfUeNgapID, ranUeNgapID, cause)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build HandoverCancel: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	ngapResp, err := t.WaitForMessage(ctx, "HandoverCancelAcknowledge", "ErrorIndication")
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for HandoverCancelAcknowledge: %v", err)
	}

	return &SendGNBUENGAPResponse{NGAP: ngapResp}, nil
}

func handleGNBHandoverRequestAcknowledge(t *transport.NGAPTransport, req *SendGNBNGAPRequest) (*SendGNBUENGAPResponse, error) {
	if req.AMFUENGAPID == nil || req.RANUENGAPID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "amf_ue_ngap_id and ran_ue_ngap_id are required")
	}

	if len(req.PDUSessions) == 0 {
		return nil, httpErrorf(http.StatusBadRequest, "pdu_sessions is required for handover_request_acknowledge")
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
				return nil, httpErrorf(http.StatusBadRequest, "decode raw_transfer: %v", err)
			}

			rawTransfer = decoded
		}

		sessions = append(sessions, ngap.HandoverAdmittedSession{PDUSessionID: ps.ID, DLTeid: teid, DLIP: dlIP, RawTransfer: rawTransfer})
	}

	encoded, err := ngap.BuildHandoverRequestAcknowledge(ngap.HandoverRequestAcknowledgeParams{
		AMFUENGAPID: *req.AMFUENGAPID,
		RANUENGAPID: *req.RANUENGAPID,
		Sessions:    sessions,
		Failed:      req.FailedPDUSessions,
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build HandoverRequestAcknowledge: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendGNBUENGAPResponse{}, nil
}

func handleGNBHandoverNotify(gnb *store.GNBContext, t *transport.NGAPTransport, req *SendGNBNGAPRequest) (*SendGNBUENGAPResponse, error) {
	if req.AMFUENGAPID == nil || req.RANUENGAPID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "amf_ue_ngap_id and ran_ue_ngap_id are required")
	}

	encoded, err := ngap.BuildHandoverNotify(ngap.HandoverNotifyParams{
		AMFUENGAPID: *req.AMFUENGAPID,
		RANUENGAPID: *req.RANUENGAPID,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GnbID:       gnb.GNBID,
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build HandoverNotify: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendGNBUENGAPResponse{}, nil
}

func handleGNBHandoverFailure(t *transport.NGAPTransport, req *SendGNBNGAPRequest) (*SendGNBUENGAPResponse, error) {
	if req.AMFUENGAPID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "amf_ue_ngap_id is required for handover_failure")
	}

	cause := ngap.CauseRadioNetworkHoFailureInTarget
	if req.Cause != nil {
		cause = *req.Cause
	}

	encoded, err := ngap.BuildHandoverFailure(*req.AMFUENGAPID, cause)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build HandoverFailure: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendGNBUENGAPResponse{}, nil
}
