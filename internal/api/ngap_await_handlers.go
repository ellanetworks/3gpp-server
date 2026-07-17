// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"

	nasCodec "github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

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
