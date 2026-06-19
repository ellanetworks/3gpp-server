// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/gtpu"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

// ENBUplinkRequest crafts an inner IP packet to send uplink on the default bearer.
type ENBUplinkRequest struct {
	ICMPEcho *struct {
		Dst string `json:"dst"`
		ID  uint16 `json:"id"`
		Seq uint16 `json:"seq"`
	} `json:"icmp_echo,omitempty"`

	// Src overrides the inner source IP (default the UE's assigned IP) — for
	// source-spoofing tests. TEID overrides the uplink TEID — for invalid-tunnel
	// tests.
	Src  *string `json:"src,omitempty"`
	TEID *uint32 `json:"teid,omitempty"`
}

// enbGTPU resolves the eNB, UE, and the eNB's S1-U GTP-U endpoint for a
// user-plane request.
func (h *Handler) enbGTPU(w http.ResponseWriter, r *http.Request) (*store.UEEPSContext, *gtpu.Endpoint, bool) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return nil, nil, false
	}

	ue, ok := enb.GetUE(r.PathValue("ue_id"))
	if !ok {
		writeError(w, http.StatusNotFound, "ue not found")
		return nil, nil, false
	}

	gt, ok := h.GTPU[enb.ID]
	if !ok {
		writeError(w, http.StatusBadRequest, "eNB has no GTP-U endpoint (create it with enable_gtpu)")
		return nil, nil, false
	}

	return ue, gt, true
}

// SendENBUplink encapsulates a crafted inner IP packet (sourced from the UE IP)
// in a plain S1-U G-PDU and sends it to the S-GW/UPF on the default bearer's
// uplink TEID.
func (h *Handler) SendENBUplink(w http.ResponseWriter, r *http.Request) {
	ue, gt, ok := h.enbGTPU(w, r)
	if !ok {
		return
	}

	if ue.ULTeid == 0 || ue.UEIP == "" {
		writeError(w, http.StatusBadRequest, "no user-plane tunnel; complete an attach on a GTP-U-enabled eNB")
		return
	}

	var req ENBUplinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.ICMPEcho == nil {
		writeError(w, http.StatusBadRequest, "icmp_echo is required")
		return
	}

	srcIP := ue.UEIP
	if req.Src != nil {
		srcIP = *req.Src
	}

	src, err := netip.ParseAddr(srcIP)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid source IP %q: %v", srcIP, err))
		return
	}

	dst, err := netip.ParseAddr(req.ICMPEcho.Dst)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid icmp_echo.dst: %v", err))
		return
	}

	inner, err := gtpu.BuildICMPEcho(src, dst, req.ICMPEcho.ID, req.ICMPEcho.Seq, []byte("3gpp-server"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ulTeid := ue.ULTeid
	if req.TEID != nil {
		ulTeid = *req.TEID
	}

	if err := gt.SendUplinkPlain(ue.UPFIP, ulTeid, inner); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("gtp-u send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"sent_bytes": len(inner)})
}

// AwaitENBDownlink blocks for a downlink T-PDU on the default bearer's eNB TEID
// and returns the decoded inner packet.
func (h *Handler) AwaitENBDownlink(w http.ResponseWriter, r *http.Request) {
	ue, gt, ok := h.enbGTPU(w, r)
	if !ok {
		return
	}

	var req struct {
		TimeoutMs int `json:"timeout_ms"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	timeout := 5 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	tpdu, err := gt.WaitForDownlink(ctx, ue.DLTeid)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}

	resp := map[string]any{"raw_hex": hex.EncodeToString(tpdu)}
	if inner, err := gtpu.ParseInner(tpdu); err == nil {
		resp["inner"] = inner
	}

	writeJSON(w, http.StatusOK, resp)
}
