// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/nas5gs"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

// An amfID of 0 means the AMF has not assigned one yet, so it cannot match.
func ueNGAPMatcher(ranID, amfID int64) func(*ngap.NGAPResponse) bool {
	return func(resp *ngap.NGAPResponse) bool {
		msgRan, msgAmf := resp.RANUENGAPID, resp.AMFUENGAPID

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

func (h *Handler) AwaitGNBUEMessage(w http.ResponseWriter, r *http.Request) {
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

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(ue.RANUENGAPID, ue.AMFUENGAPID), req.MessageTypes...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.MessageTypes, err))
		return
	}

	writeJSON(w, http.StatusOK, SendGNBUENGAPResponse{NGAP: ngapResp, NAS: decodeNASFromNGAP(ue, ngapResp)})
}

func decodeNASFromNGAP(ue *store.UEContext, ngapResp *ngap.NGAPResponse) *nas5gs.NASResponse {
	var nasResp *nas5gs.NASResponse

	if ngapResp.NasPDU != nil {
		if nasPDUBytes, err := hex.DecodeString(*ngapResp.NasPDU); err == nil {
			nasResp, _ = decodeGNBDownlinkNAS(ue, nasPDUBytes)
		}
	}

	return nasResp
}

func (h *Handler) AwaitGNBMessage(w http.ResponseWriter, r *http.Request) {
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

	writeJSON(w, http.StatusOK, SendGNBUENGAPResponse{NGAP: ngapResp})
}
