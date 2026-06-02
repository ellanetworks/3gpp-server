package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/store"
)

func (h *Handler) CreateUE(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	gnb, err := h.Store.GetGnB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	var req CreateUERequest
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

	ranUeNgapID := gnb.AllocateRanUeNgapID()
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
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to create UE context: %v", err))
		return
	}

	gnb.CreateUE(ue)

	writeJSON(w, http.StatusCreated, CreateUEResponse{
		UEID:        ue.ID,
		SUPI:        ue.Supi,
		SUCI:        ue.SuciString,
		RanUeNgapID: ue.RanUeNgapID,
	})
}

func (h *Handler) GetUE(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGnB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	ue, ok := gnb.GetUE(ueID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return
	}

	writeJSON(w, http.StatusOK, UEStateResponse{
		ID:               ue.ID,
		SUPI:             ue.Supi,
		SUCI:             ue.SuciString,
		MCC:              ue.MCC,
		MNC:              ue.MNC,
		RanUeNgapID:      ue.RanUeNgapID,
		AmfUeNgapID:      ue.AmfUeNgapID,
		K:                ue.K,
		OPc:              ue.OPc,
		Amf:              ue.Amf,
		Sqn:              ue.Sqn,
		Snn:              ue.Snn,
		DNN:              ue.DNN,
		SST:              ue.SST,
		SD:               ue.SD,
		ProtectionScheme: ue.ProtectionScheme,
		RoutingIndicator: ue.RoutingIndicator,
		IMEISV:           ue.IMEISV,
	})
}

func (h *Handler) PatchUE(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGnB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	ue, ok := gnb.GetUE(ueID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return
	}

	var req PatchUERequest
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
	if req.AmfUeNgapID != nil {
		ue.AmfUeNgapID = *req.AmfUeNgapID
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

func (h *Handler) DeleteUE(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGnB(gnbID)
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

// MigrateUE moves a UE's context to another gNB's association, modelling the UE
// arriving at the target gNB after an N2 handover. The UE keeps its security
// context; its RAN/AMF UE NGAP IDs become the ones used on the target.
func (h *Handler) MigrateUE(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	src, err := h.Store.GetGnB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	ue, ok := src.GetUE(ueID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return
	}

	var req MigrateUERequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	target, err := h.Store.GetGnB(req.TargetGnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("target gnb not found: %v", err))
		return
	}

	if req.RanUeNgapID != nil {
		ue.RanUeNgapID = *req.RanUeNgapID
	}

	if req.AmfUeNgapID != nil {
		ue.AmfUeNgapID = *req.AmfUeNgapID
	}

	src.DeleteUE(ueID)
	target.CreateUE(ue)
	target.UpdateNGAPIDs(ue.RanUeNgapID, ue.AmfUeNgapID)

	writeJSON(w, http.StatusOK, map[string]any{
		"ue_id":          ue.ID,
		"gnb_id":         req.TargetGnbID,
		"ran_ue_ngap_id": ue.RanUeNgapID,
		"amf_ue_ngap_id": ue.AmfUeNgapID,
	})
}
