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
	"strconv"

	"github.com/ellanetworks/3gpp-server/internal/gtpu"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

type GNBUplinkRequest struct {
	PDUSessionID int64 `json:"pdu_session_id,omitempty"`

	TEID *uint32 `json:"teid,omitempty"`

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

	Src *string `json:"src,omitempty"`
}

type GNBAwaitDownlinkRequest struct {
	PDUSessionID int64 `json:"pdu_session_id,omitempty"`
	TimeoutMs    int   `json:"timeout_ms,omitempty"`
}

func (h *Handler) gnbGTPU(w http.ResponseWriter, r *http.Request, pduSessionID int64) (*gtpu.Endpoint, *store.PDUSessionInfo, bool) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGNB(gnbID)
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

	info, ok := ue.PDUSessions[uint8(pduSessionID)]
	if !ok || info.ULTeid == 0 || info.UEIP == "" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("no established N3 tunnel for PDU session %d", pduSessionID))
		return nil, nil, false
	}

	return gt, info, true
}

func (h *Handler) SendGNBUplink(w http.ResponseWriter, r *http.Request) {
	var req GNBUplinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	gt, info, ok := h.gnbGTPU(w, r, req.PDUSessionID)
	if !ok {
		return
	}

	srcIP := info.UEIP
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

	qfi := info.QFI
	if qfi == 0 {
		qfi = 1
	}

	ulTeid := info.ULTeid
	if req.TEID != nil {
		ulTeid = *req.TEID
	}

	if err := gt.SendUplink(info.UPFIP, ulTeid, qfi, inner); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("gtp-u send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"sent_bytes": len(inner)})
}

func (h *Handler) AwaitGNBDownlink(w http.ResponseWriter, r *http.Request) {
	var req GNBAwaitDownlinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	gt, info, ok := h.gnbGTPU(w, r, req.PDUSessionID)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	msg, err := gt.WaitForDownlink(ctx, info.DLTeid)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}

	resp := map[string]any{"raw_hex": hex.EncodeToString(msg.Payload)}
	if inner, err := gtpu.ParseInner(msg.Payload); err == nil {
		resp["inner"] = inner
	}

	if msg.PDUSession != nil {
		resp["pdu_session_container"] = msg.PDUSession
	}

	writeJSON(w, http.StatusOK, resp)
}

type GNBTunnelResponse struct {
	PDUSessionID uint8  `json:"pdu_session_id"`
	DNN          string `json:"dnn,omitempty"`
	N3GNBIP      string `json:"n3_gnb_ip"`
	DLTeid       uint32 `json:"dl_teid"`
	QFI          uint8  `json:"qfi"`
	ULTeid       uint32 `json:"ul_teid,omitempty"`
	UPFIP        string `json:"upf_ip,omitempty"`
	UEIP         string `json:"ue_ip,omitempty"`
}

func (h *Handler) GetGNBTunnel(w http.ResponseWriter, r *http.Request) {
	pduSessionID := int64(0)
	if v := r.URL.Query().Get("pdu_session_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			pduSessionID = n
		}
	}

	_, info, ok := h.gnbGTPU(w, r, pduSessionID)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, GNBTunnelResponse{
		PDUSessionID: info.PDUSessionID,
		DNN:          info.DNN,
		N3GNBIP:      info.N3GNBIP,
		DLTeid:       info.DLTeid,
		QFI:          info.QFI,
		ULTeid:       info.ULTeid,
		UPFIP:        info.UPFIP,
		UEIP:         info.UEIP,
	})
}

func (h *Handler) SendGNBGTPUEcho(w http.ResponseWriter, r *http.Request) {
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

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	msg, err := gt.WaitForControl(ctx, gtpu.MsgEchoResponse)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}

	resp := map[string]any{"echo_response": true, "seq": msg.Seq}
	if msg.Recovery != nil {
		resp["recovery_restart_counter"] = *msg.Recovery
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) AwaitGNBErrorIndication(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	var req struct {
		TimeoutMs int `json:"timeout_ms,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	gt, ok := h.GTPU[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no GTP-U endpoint (create it with enable_gtpu)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	msg, err := gt.WaitForControl(ctx, gtpu.MsgErrorIndication)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, errorIndicationJSON(msg))
}

func errorIndicationJSON(msg *gtpu.Message) map[string]any {
	resp := map[string]any{"error_indication": true, "header_teid": msg.TEID}
	if msg.TEIDDataI != nil {
		resp["teid_data_i"] = *msg.TEIDDataI
	}

	if msg.PeerAddress != "" {
		resp["gtpu_peer_address"] = msg.PeerAddress
	}

	return resp
}
