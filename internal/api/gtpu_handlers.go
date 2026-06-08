package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/gtpu"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

// UplinkRequest crafts an inner IP packet and sends it uplink through the N3
// tunnel. Exactly one of icmp_echo / udp is used.
type UplinkRequest struct {
	PDUSessionID int64 `json:"pdu_session_id,omitempty"`

	ICMPEcho *struct {
		Dst string `json:"dst"`
		ID  uint16 `json:"id,omitempty"`
		Seq uint16 `json:"seq,omitempty"`
	} `json:"icmp_echo,omitempty"`

	UDP *struct {
		Dst        string `json:"dst"`
		DstPort    uint16 `json:"dst_port"`
		SrcPort    uint16 `json:"src_port,omitempty"`
		PayloadHex string `json:"payload_hex,omitempty"`
	} `json:"udp,omitempty"`
}

// AwaitDownlinkRequest blocks for a downlink T-PDU on a session's DL TEID.
type AwaitDownlinkRequest struct {
	PDUSessionID int64 `json:"pdu_session_id,omitempty"`
	TimeoutMs    int   `json:"timeout_ms,omitempty"`
}

// gtpuSession resolves the GTP-U endpoint and tunnel state for a UE-associated
// data-plane request, writing the appropriate error on failure.
func (h *Handler) gtpuSession(w http.ResponseWriter, r *http.Request, pduSessionID int64) (*gtpu.Endpoint, *store.PDUSessionInfo, bool) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGnB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return nil, nil, false
	}

	ue, ok := gnb.GetUE(ueID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return nil, nil, false
	}

	gt, ok := h.GTPU[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no GTP-U endpoint (create it with enable_gtpu)")
		return nil, nil, false
	}

	if pduSessionID == 0 {
		pduSessionID = int64(ue.PDUSessionID)
		if pduSessionID == 0 {
			pduSessionID = 1
		}
	}

	info, ok := gnb.GetPDUSession(ue.RanUeNgapID, pduSessionID)
	if !ok || info.ULTeid == 0 || info.UEIP == "" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("no established N3 tunnel for PDU session %d", pduSessionID))
		return nil, nil, false
	}

	return gt, info, true
}

// SendUplink encapsulates a crafted inner IP packet (sourced from the UE IP) and
// sends it to the UPF on the session's uplink tunnel.
func (h *Handler) SendUplink(w http.ResponseWriter, r *http.Request) {
	var req UplinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	gt, info, ok := h.gtpuSession(w, r, req.PDUSessionID)
	if !ok {
		return
	}

	ueIP, err := netip.ParseAddr(info.UEIP)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("invalid UE IP %q: %v", info.UEIP, err))
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

		inner, err = gtpu.BuildICMPEcho(ueIP, dst, req.ICMPEcho.ID, req.ICMPEcho.Seq, []byte("3gpp-server"))
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

		inner, err = gtpu.BuildUDP(ueIP, dst, srcPort, req.UDP.DstPort, payload)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

	default:
		writeError(w, http.StatusBadRequest, "one of icmp_echo or udp is required")
		return
	}

	qfi := info.QFI
	if qfi == 0 {
		qfi = 1
	}

	if err := gt.SendUplink(info.UPFIP, info.ULTeid, qfi, inner); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("gtp-u send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"sent_bytes": len(inner)})
}

// AwaitDownlink blocks for a downlink T-PDU on the session's DL TEID and returns
// the decoded inner packet.
func (h *Handler) AwaitDownlink(w http.ResponseWriter, r *http.Request) {
	var req AwaitDownlinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	gt, info, ok := h.gtpuSession(w, r, req.PDUSessionID)
	if !ok {
		return
	}

	timeout := 5 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	tpdu, err := gt.WaitForDownlink(ctx, info.DLTeid)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}

	resp := map[string]any{"raw_hex": hex.EncodeToString(tpdu)}
	if inner, err := gtpu.ParseIPv4(tpdu); err == nil {
		resp["inner"] = inner
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetTunnel returns the stored N3 tunnel state for a UE's PDU session.
func (h *Handler) GetTunnel(w http.ResponseWriter, r *http.Request) {
	pduSessionID := int64(0)
	if v := r.URL.Query().Get("pdu_session_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			pduSessionID = n
		}
	}

	_, info, ok := h.gtpuSession(w, r, pduSessionID)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, info)
}

// SendGTPUEcho sends a GTP-U Echo Request to the UPF and returns its Echo
// Response (TS 29.281 §7.2.1).
func (h *Handler) SendGTPUEcho(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	var req struct {
		UPFIP     string `json:"upf_ip"`
		TimeoutMs int    `json:"timeout_ms,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	gt, ok := h.GTPU[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no GTP-U endpoint (create it with enable_gtpu)")
		return
	}

	if req.UPFIP == "" {
		writeError(w, http.StatusBadRequest, "upf_ip is required")
		return
	}

	if err := gt.SendEchoRequest(req.UPFIP, 1); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("gtp-u echo send: %v", err))
		return
	}

	timeout := 5 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	msg, err := gt.WaitForControl(ctx, gtpu.MsgEchoResponse)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"echo_response": true, "seq": msg.Seq})
}
