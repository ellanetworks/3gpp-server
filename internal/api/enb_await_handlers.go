// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

func (h *Handler) AwaitENBMessage(w http.ResponseWriter, r *http.Request) {
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

	req, ok := decodeAwaitRequest(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), req.timeout)
	defer cancel()

	resp, err := t.WaitForMessage(ctx, req.MessageTypes...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.MessageTypes, err))
		return
	}

	writeJSON(w, http.StatusOK, SendENBUES1APResponse{S1AP: resp})
}

func (h *Handler) AwaitENBUEMessage(w http.ResponseWriter, r *http.Request) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	ue, ok := enb.GetUE(r.PathValue("ue_id"))
	if !ok {
		writeError(w, http.StatusNotFound, "ue not found")
		return
	}

	t, ok := h.S1APTransports[enb.ID]
	if !ok {
		writeError(w, http.StatusNotFound, "enb has no S1-MME association")
		return
	}

	req, ok := decodeAwaitRequest(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), req.timeout)
	defer cancel()

	resp, err := t.WaitForMessageMatching(ctx, s1apUEMatcher(ue.MMEUES1APID, ue.ENBUES1APID), req.MessageTypes...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.MessageTypes, err))
		return
	}

	writeJSON(w, http.StatusOK, SendENBUES1APResponse{S1AP: resp, NAS: decodeNASFromS1AP(ue, resp)})
}

func decodeNASFromS1AP(ue *store.UEEPSContext, resp *s1ap.S1APResponse) *naseps.NASResponse {
	var nasResp *naseps.NASResponse

	if resp.NASPDU != nil {
		if b, err := hex.DecodeString(*resp.NASPDU); err == nil {
			nasResp, _ = decodeENBDownlinkNAS(ue, b)
		}
	}

	return nasResp
}

// An mmeID of 0 means the MME has not assigned one yet, so it cannot match.
func s1apUEMatcher(mmeID, enbID uint32) func(*s1ap.S1APResponse) bool {
	return func(resp *s1ap.S1APResponse) bool {
		if resp.MMEUES1APID == nil && resp.ENBUES1APID == nil {
			return true
		}

		if resp.ENBUES1APID != nil && *resp.ENBUES1APID == int64(enbID) {
			return true
		}

		if resp.MMEUES1APID != nil && mmeID != 0 && *resp.MMEUES1APID == int64(mmeID) {
			return true
		}

		return false
	}
}
