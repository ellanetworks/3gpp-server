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

	"github.com/ellanetworks/3gpp-server/internal/gtpu"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

// ENBUplinkRequest crafts an inner IP packet to send uplink on an EPS bearer.
type ENBUplinkRequest struct {
	// Ebi selects the bearer; 0 or the default EBI uses the default bearer, else
	// an additional PDN's bearer (TS 24.301 §6.5.1).
	Ebi uint8 `json:"ebi,omitempty"`

	ICMPEcho *struct {
		Dst string `json:"dst"`
		ID  uint16 `json:"id"`
		Seq uint16 `json:"seq"`
	} `json:"icmp_echo,omitempty"`

	UDP *struct {
		Dst        string `json:"dst"`
		DstPort    uint16 `json:"dst_port"`
		SrcPort    uint16 `json:"src_port,omitempty"`
		PayloadHex string `json:"payload_hex,omitempty"`
	} `json:"udp,omitempty"`

	// Src overrides the inner source IP (default the selected bearer's UE IP) — for
	// source-spoofing tests. TEID overrides the uplink TEID — for invalid-tunnel
	// tests.
	Src  *string `json:"src,omitempty"`
	TEID *uint32 `json:"teid,omitempty"`
}

// enbBearer resolves the S1-U tunnel for the selected EPS bearer identity: the
// default bearer when ebi is 0 or the default EBI, else an additional PDN's
// bearer. The inner packet must be sourced from the returned ueIP or the UPF's
// anti-spoofing filter drops it.
func enbBearer(ue *store.UEEPSContext, ebi uint8) (ulTeid, dlTeid uint32, upfIP, ueIP string, ok bool) {
	if ebi == 0 || ebi == ue.EPSBearerID {
		return ue.ULTeid, ue.DLTeid, ue.UPFIP, ue.UEIP, ue.ULTeid != 0
	}

	b, exists := ue.Bearers[ebi]
	if !exists {
		return 0, 0, "", "", false
	}

	return b.ULTeid, b.DLTeid, b.UPFIP, b.UEIP, true
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

// SendENBUplink encapsulates a crafted inner IP packet (sourced from the bearer's
// UE IP) in a plain S1-U G-PDU and sends it to the S-GW/UPF on the selected
// bearer's uplink TEID.
func (h *Handler) SendENBUplink(w http.ResponseWriter, r *http.Request) {
	ue, gt, ok := h.enbGTPU(w, r)
	if !ok {
		return
	}

	var req ENBUplinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ulTeid, _, upfIP, ueIP, found := enbBearer(ue, req.Ebi)
	if !found {
		writeError(w, http.StatusBadRequest, "no user-plane tunnel for the selected bearer; complete an attach / pdn_connectivity on a GTP-U-enabled eNB")
		return
	}

	srcIP := ueIP
	if req.Src != nil {
		srcIP = *req.Src
	}

	src, err := netip.ParseAddr(srcIP)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid source IP %q: %v", srcIP, err))
		return
	}

	var inner []byte

	switch {
	case req.ICMPEcho != nil:
		dst, err := netip.ParseAddr(req.ICMPEcho.Dst)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid icmp_echo.dst: %v", err))
			return
		}

		inner, err = gtpu.BuildICMPEcho(src, dst, req.ICMPEcho.ID, req.ICMPEcho.Seq, []byte("3gpp-server"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

	case req.UDP != nil:
		dst, err := netip.ParseAddr(req.UDP.Dst)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid udp.dst: %v", err))
			return
		}

		payload, err := hex.DecodeString(req.UDP.PayloadHex)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid udp.payload_hex: %v", err))
			return
		}

		srcPort := req.UDP.SrcPort
		if srcPort == 0 {
			srcPort = 12345
		}

		inner, err = gtpu.BuildUDP(src, dst, srcPort, req.UDP.DstPort, payload)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

	default:
		writeError(w, http.StatusBadRequest, "one of icmp_echo or udp is required")
		return
	}

	if req.TEID != nil {
		ulTeid = *req.TEID
	}

	if err := gt.SendUplinkPlain(upfIP, ulTeid, inner); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("gtp-u send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"sent_bytes": len(inner)})
}

// SendENBGTPUEcho sends a GTP-U Echo Request to the S-GW/UPF on S1-U and returns
// its Echo Response (TS 29.281 §7.2.1).
func (h *Handler) SendENBGTPUEcho(w http.ResponseWriter, r *http.Request) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	gt, ok := h.GTPU[enb.ID]
	if !ok {
		writeError(w, http.StatusBadRequest, "eNB has no GTP-U endpoint (create it with enable_gtpu)")
		return
	}

	var req struct {
		UPFIP     string `json:"upf_ip"`
		TimeoutMs int    `json:"timeout_ms,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.UPFIP == "" {
		writeError(w, http.StatusBadRequest, "upf_ip is required")
		return
	}

	if err := gt.SendEchoRequest(req.UPFIP, 1); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("gtp-u echo send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	msg, err := gt.WaitForControl(ctx, gtpu.MsgEchoResponse)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"echo_response": true, "seq": msg.Seq})
}

// AwaitENBErrorIndication blocks for a GTP-U Error Indication from the S-GW/UPF,
// sent when it receives a G-PDU on S1-U for a TEID with no context (TS 29.281
// §7.3.1).
func (h *Handler) AwaitENBErrorIndication(w http.ResponseWriter, r *http.Request) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	gt, ok := h.GTPU[enb.ID]
	if !ok {
		writeError(w, http.StatusBadRequest, "eNB has no GTP-U endpoint (create it with enable_gtpu)")
		return
	}

	var req struct {
		TimeoutMs int `json:"timeout_ms,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	if _, err := gt.WaitForControl(ctx, gtpu.MsgErrorIndication); err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"error_indication": true})
}

// AwaitENBDownlink blocks for a downlink T-PDU on the selected bearer's eNB TEID
// and returns the decoded inner packet.
func (h *Handler) AwaitENBDownlink(w http.ResponseWriter, r *http.Request) {
	ue, gt, ok := h.enbGTPU(w, r)
	if !ok {
		return
	}

	var req struct {
		Ebi       uint8 `json:"ebi,omitempty"`
		TimeoutMs int   `json:"timeout_ms"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	_, dlTeid, _, _, found := enbBearer(ue, req.Ebi)
	if !found {
		writeError(w, http.StatusBadRequest, "no user-plane tunnel for the selected bearer")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	tpdu, err := gt.WaitForDownlink(ctx, dlTeid)
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
