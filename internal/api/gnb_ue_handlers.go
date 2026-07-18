// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"fmt"
	"net/http"

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

	writeJSON(w, http.StatusOK, GNBUEStateResponse{
		ID:               ue.ID,
		SUPI:             ue.Supi,
		SUCI:             ue.SuciString,
		MCC:              ue.MCC,
		MNC:              ue.MNC,
		RANUENGAPID:      ue.RANUENGAPID,
		AMFUENGAPID:      ue.AMFUENGAPID,
		K:                ue.K,
		OPc:              ue.OPc,
		Amf:              ue.Amf,
		Sqn:              ue.Sqn,
		DNN:              ue.DNN,
		SST:              ue.SST,
		SD:               ue.SD,
		ProtectionScheme: ue.ProtectionScheme,
		RoutingIndicator: ue.RoutingIndicator,
		IMEISV:           ue.IMEISV,
	})
}

func (h *Handler) PatchGNBUE(w http.ResponseWriter, r *http.Request) {
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

	var req PatchGNBUERequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.K != nil {
		ue.K = *req.K
	}
	if req.OPc != nil {
		ue.OPc = *req.OPc
	}
	if req.Amf != nil {
		ue.Amf = *req.Amf
	}
	if req.Sqn != nil {
		ue.Sqn = *req.Sqn
	}
	if req.AMFUENGAPID != nil {
		ue.AMFUENGAPID = *req.AMFUENGAPID
	}
	if req.DNN != nil {
		ue.DNN = *req.DNN
	}
	if req.SST != nil {
		ue.SST = *req.SST
	}
	if req.SD != nil {
		ue.SD = *req.SD
	}
	if req.IMEISV != nil {
		ue.IMEISV = *req.IMEISV
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteGNBUE(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGNB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	if !gnb.DeleteUE(ueID) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) MigrateGNBUE(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	src, err := h.Store.GetGNB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	ue, ok := src.GetUE(ueID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return
	}

	var req MigrateGNBUERequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	target, err := h.Store.GetGNB(req.TargetGnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("target gnb not found: %v", err))
		return
	}

	src.MigrateUE(target, ue, req.RANUENGAPID, req.AMFUENGAPID)

	writeJSON(w, http.StatusOK, MigrateGNBUEResponse{
		UEID:        ue.ID,
		GNBID:       req.TargetGnbID,
		RANUENGAPID: ue.RANUENGAPID,
		AMFUENGAPID: ue.AMFUENGAPID,
	})
}
