// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/ellanetworks/3gpp-server/internal/store"
)

func (h *Handler) CreateGNBUE(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	gnb, err := h.Store.GetGNB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	var req CreateGNBUERequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.SUPI == "" {
		writeError(w, http.StatusBadRequest, "supi is required")
		return
	}
	if req.K == "" {
		writeError(w, http.StatusBadRequest, "k is required")
		return
	}
	if req.OPc == "" {
		writeError(w, http.StatusBadRequest, "opc is required")
		return
	}

	ranUeNgapID := gnb.AllocateRANUENGAPID()
	ueID := fmt.Sprintf("%d", ranUeNgapID)

	ue, err := store.NewUEContext(ueID, ranUeNgapID, len(gnb.MNC), &store.CreateUEOpts{
		Supi:             req.SUPI,
		K:                req.K,
		OPc:              req.OPc,
		Amf:              req.Amf,
		Sqn:              req.Sqn,
		SST:              req.SST,
		SD:               req.SD,
		DNN:              req.DNN,
		RoutingIndicator: req.RoutingIndicator,
		ProtectionScheme: req.ProtectionScheme,
		PublicKeyID:      req.PublicKeyID,
		PublicKeyHex:     req.PublicKeyHex,
		PDUSessionID:     req.PDUSessionID,
		PDUSessionType:   req.PDUSessionType,
		IMEISV:           req.IMEISV,

		UESecurityCapability: req.UESecurityCapability,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to create UE context: %v", err))
		return
	}

	gnb.CreateUE(ue)

	writeJSON(w, http.StatusCreated, CreateGNBUEResponse{
		UEID:        ue.ID,
		SUPI:        ue.Supi,
		SUCI:        ue.SuciString,
		RANUENGAPID: ue.RANUENGAPID,
	})
}

func (h *Handler) GetGNBUE(w http.ResponseWriter, r *http.Request) {
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

	ids := make([]int, 0, len(ue.PDUSessions))
	for id := range ue.PDUSessions {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)

	sessions := make([]GNBUESession, 0, len(ids))
	for _, id := range ids {
		s := ue.PDUSessions[uint8(id)]
		sessions = append(sessions, GNBUESession{PDUSessionID: s.PDUSessionID, UEIP: s.UEIP})
	}

	var ueIP string
	if def, ok := ue.PDUSessions[ue.PDUSessionID]; ok {
		ueIP = def.UEIP
	} else if len(sessions) > 0 {
		ueIP = sessions[0].UEIP
	}

	writeJSON(w, http.StatusOK, GNBUEStateResponse{
		UEID:                ue.ID,
		SUPI:                ue.Supi,
		SUCI:                ue.SuciString,
		IMEISV:              ue.IMEISV,
		UEIP:                ueIP,
		SecurityActive:      ue.SecurityActive,
		RANUENGAPID:         ue.RANUENGAPID,
		AMFUENGAPID:         ue.AMFUENGAPID,
		DefaultPDUSessionID: ue.PDUSessionID,
		Sessions:            sessions,
		DNN:                 ue.DNN,
		SST:                 ue.SST,
		SD:                  ue.SD,
		ProtectionScheme:    ue.ProtectionScheme,
		RoutingIndicator:    ue.RoutingIndicator,
	})
}
