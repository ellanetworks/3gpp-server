// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ellanetworks/3gpp-server/internal/store"
)

func (h *Handler) CreateENBUE(w http.ResponseWriter, r *http.Request) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	var req CreateENBUERequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	imsi := strings.TrimPrefix(req.IMSI, "imsi-")
	if imsi == "" {
		writeError(w, http.StatusBadRequest, "imsi is required")
		return
	}

	enbUES1APID := enb.AllocateENBUES1APID()
	ueID := fmt.Sprintf("%d", enbUES1APID)

	ue := store.NewUEEPSContext(ueID, enbUES1APID, &store.CreateUEEPSOpts{
		IMSI:   imsi,
		IMEISV: req.IMEISV,
		K:      req.K,
		OPc:    req.OPc,
		AMF:    req.AMF,
		SQN:    req.SQN,
	})

	if req.UENetworkCapability != "" {
		cap, err := hex.DecodeString(req.UENetworkCapability)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("ue_network_capability must be hex: %v", err))
			return
		}

		ue.UENetworkCapability = cap
	}

	enb.CreateUE(ue)

	writeJSON(w, http.StatusCreated, CreateENBUEResponse{UEID: ue.ID, ENBUES1APID: ue.ENBUES1APID})
}

func (h *Handler) GetENBUE(w http.ResponseWriter, r *http.Request) {
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

	bearers := make([]ENBUEBearer, 0, len(ue.Bearers))
	for _, b := range ue.Bearers {
		bearers = append(bearers, ENBUEBearer{EBI: b.EBI, APN: b.APN, UEIP: b.UEIP})
	}

	writeJSON(w, http.StatusOK, ENBUEStateResponse{
		UEID:           ue.ID,
		IMSI:           ue.IMSI,
		IMEISV:         ue.IMEISV,
		UEIP:           ue.UEIP,
		SecurityActive: ue.SecurityActive,
		MMEUES1APID:    ue.MMEUES1APID,
		ENBUES1APID:    ue.ENBUES1APID,
		DefaultEBI:     ue.EPSBearerID,
		Bearers:        bearers,
	})
}

// TS 24.301 §9.9.3.9.
const emmCauseSecurityCapMismatch uint8 = 23

// TS 24.301 §9.9.4.4.
const esmCauseProtocolErrorUnspec uint8 = 111
