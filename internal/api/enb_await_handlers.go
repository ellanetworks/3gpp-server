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

	writeJSON(w, http.StatusOK, SendENBNASResponse{S1AP: resp})
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

	writeJSON(w, http.StatusOK, SendENBNASResponse{S1AP: resp, NAS: decodeENBDownlinkNAS(ue, resp)})
}

// b[5] is the sequence number, which is the DL NAS COUNT until the first overflow.
func decodeENBDownlinkNAS(ue *store.UEEPSContext, resp *s1ap.S1APResponse) *naseps.NASResponse {
	if resp == nil || resp.NASPDU == nil {
		return nil
	}

	b, err := hex.DecodeString(*resp.NASPDU)
	if err != nil {
		return nil
	}

	sht, err := naseps.SecurityHeader(b)
	if err != nil {
		return nil
	}

	if sht == naseps.SHTPlain {
		nas, _ := naseps.Decode(b)
		return annotateSecurityHeaderType(nas, b)
	}

	if !ue.SecurityActive || len(b) < 6 {
		return nil
	}

	plain, err := naseps.Unprotect(b, uint32(b[5]), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil
	}

	nas, _ := naseps.Decode(plain)

	return annotateSecurityHeaderType(nas, b)
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
