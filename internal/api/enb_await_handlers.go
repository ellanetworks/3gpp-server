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

// AwaitENBMessage waits for an unsolicited non-UE-associated S1AP message on the
// eNB's S1-MME association — e.g. a PAGING the MME broadcasts to reach an
// ECM-IDLE UE (TS 36.413 §9.1.6), or an MME-initiated Reset.
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

// AwaitENBUEMessage waits for an unsolicited UE-associated downlink S1AP message
// addressed to a specific UE — e.g. a network-initiated DETACH REQUEST or a
// Modify EPS Bearer Context Request — letting many UEs share one eNB association
// without claiming each other's downlink.
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

// decodeENBDownlinkNAS best-effort decodes the EPS NAS message carried in a
// downlink S1AP PDU (e.g. the Detach Request in a Downlink NAS Transport),
// returning nil when the PDU carries none or cannot be decoded. A protected
// message is unprotected under the UE's NAS keys; its DL NAS COUNT is taken from
// the message sequence number (the overflow counter is 0 below 256 downlinks).
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
		return nas
	}

	if !ue.SecurityActive || len(b) < 6 {
		return nil
	}

	plain, err := naseps.Unprotect(b, uint32(b[5]), ue.EIA, ue.EEA, ue.KnasInt, ue.KnasEnc)
	if err != nil {
		return nil
	}

	nas, _ := naseps.Decode(plain)

	return nas
}

// s1apUEMatcher matches a downlink S1AP PDU to a specific UE by its S1AP ID pair,
// so concurrent waiters on one eNB association don't consume each other's
// downlink. The eNB UE S1AP ID is ours (always known) and matched exactly. The
// MME UE S1AP ID is the MME's to assign, so an mmeID of 0 means "not yet known"
// and is skipped. A PDU carrying neither ID (e.g. a Paging) matches any waiter.
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
