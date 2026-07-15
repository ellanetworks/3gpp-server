// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/gtpu"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

// ErrorIndication is included because a strict MME may return one for a bad
// request.
var defaultS1SetupWait = []string{"S1SetupResponse", "S1SetupFailure", "ErrorIndication"}

func (h *Handler) CreateENB(w http.ResponseWriter, r *http.Request) {
	var req CreateENBRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.MMEAddress == "" {
		writeError(w, http.StatusBadRequest, "mme_address is required")
		return
	}

	raw := req.RawS1APPDU != nil

	var tac uint64
	if req.TAC != "" {
		parsed, err := strconv.ParseUint(req.TAC, 16, 16)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("tac must be a 2-octet hex string: %v", err))
			return
		}

		tac = parsed
	} else if !raw {
		writeError(w, http.StatusBadRequest, "tac is required")
		return
	}

	encoded, err := encodeS1SetupAttempt(&req, uint16(tac))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	localAddr := req.ENBS1Address
	if localAddr == "" {
		localAddr = "0.0.0.0"
	}

	t, err := transport.DialS1AP(localAddr, req.MMEAddress)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sctp dial failed: %v", err))
		return
	}

	enb := h.Store.CreateENB(req.MCC, req.MNC, uint16(tac), req.ENBID, req.Name)
	enb.N3Addr = localAddr
	h.S1APTransports[enb.ID] = t

	if req.EnableGTPU {
		n3 := req.ENBN3Address
		if n3 == "" {
			n3 = localAddr
		}

		gt, err := gtpu.Listen(n3)
		if err != nil {
			h.teardownENB(enb.ID, t)
			writeError(w, http.StatusBadGateway, fmt.Sprintf("gtp-u listen on %s failed: %v", n3, err))
			return
		}

		enb.N3Addr = n3
		h.GTPU[enb.ID] = gt
	}

	// Models an eNB that has not completed S1 Setup (TS 36.413 §8.7.1).
	if req.SkipS1Setup {
		writeJSON(w, http.StatusCreated, CreateENBResponse{ENBID: enb.ID})
		return
	}

	if err := t.Send(encoded, true); err != nil {
		h.teardownENB(enb.ID, t)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sctp send: %v", err))
		return
	}

	waitFor := req.WaitFor
	if len(waitFor) == 0 {
		waitFor = defaultS1SetupWait
	}

	timeout := waitTimeout(req.TimeoutMs)
	if raw && req.TimeoutMs == 0 {
		timeout = 2 * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	resp, err := t.WaitForMessage(ctx, waitFor...)
	if err != nil {
		// An MME may validly drop a malformed PDU without replying; the association
		// is kept so the caller can probe it further.
		if raw {
			writeJSON(w, http.StatusCreated, CreateENBResponse{ENBID: enb.ID})
			return
		}

		h.teardownENB(enb.ID, t)
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for S1 Setup outcome: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, CreateENBResponse{
		ENBID:    enb.ID,
		Response: resp,
	})
}

func encodeS1SetupAttempt(req *CreateENBRequest, tac uint16) ([]byte, error) {
	if req.RawS1APPDU != nil {
		b, err := hex.DecodeString(*req.RawS1APPDU)
		if err != nil {
			return nil, fmt.Errorf("raw_s1ap_pdu must be hex: %v", err)
		}

		return b, nil
	}

	encoded, err := s1ap.BuildS1SetupRequest(&s1ap.S1SetupRequestParams{
		MCC:     req.MCC,
		MNC:     req.MNC,
		ENBID:   req.ENBID,
		ENBName: req.Name,
		TAC:     tac,
	})
	if err != nil {
		return nil, fmt.Errorf("s1ap encode: %v", err)
	}

	return encoded, nil
}

func (h *Handler) GetENB(w http.ResponseWriter, r *http.Request) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ENBStateResponse{
		ID:    enb.ID,
		MCC:   enb.MCC,
		MNC:   enb.MNC,
		TAC:   fmt.Sprintf("%04x", enb.TAC),
		ENBID: enb.ENBID,
		Name:  enb.Name,
	})
}

func (h *Handler) DeleteENB(w http.ResponseWriter, r *http.Request) {
	enbID := r.PathValue("enb_id")

	if t, ok := h.S1APTransports[enbID]; ok {
		_ = t.Close()
		delete(h.S1APTransports, enbID)
	}

	if gt, ok := h.GTPU[enbID]; ok {
		_ = gt.Close()
		delete(h.GTPU, enbID)
	}

	if err := h.Store.DeleteENB(enbID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) teardownENB(id string, t *transport.S1APTransport) {
	_ = t.Close()

	if gt, ok := h.GTPU[id]; ok {
		_ = gt.Close()
		delete(h.GTPU, id)
	}

	_ = h.Store.DeleteENB(id)
	delete(h.S1APTransports, id)
}
