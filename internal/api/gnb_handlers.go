package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

type Handler struct {
	Store      *store.Store
	Transports map[string]*transport.SCTPTransport // gnb store ID -> transport
}

func NewHandler(s *store.Store) *Handler {
	return &Handler{
		Store:      s,
		Transports: make(map[string]*transport.SCTPTransport),
	}
}

func (h *Handler) CreateGnB(w http.ResponseWriter, r *http.Request) {
	var req CreateGnBRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.AMFAddress == "" {
		writeError(w, http.StatusBadRequest, "amf_address is required")
		return
	}

	localAddr := req.GnBN2Address
	if localAddr == "" {
		localAddr = "0.0.0.0"
	}

	t, err := transport.Dial(localAddr, req.AMFAddress)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sctp dial failed: %v", err))
		return
	}

	slices := make([]store.SliceConfig, 0, len(req.Slices))
	for _, s := range req.Slices {
		slices = append(slices, store.SliceConfig{SST: s.SST, SD: s.SD})
	}

	gnb := h.Store.CreateGnB(req.MCC, req.MNC, req.TAC, req.GnbID, req.Name, req.SST, req.SD, slices)
	h.Transports[gnb.ID] = t

	var msg *ngap.NGAPMessage
	if len(req.NGSetupIEs) > 0 {
		msg = &ngap.NGAPMessage{
			ProcedureCode: 21, // NGSetup
			PDUType:       "initiating_message",
			Criticality:   "reject",
			IEs:           req.NGSetupIEs,
		}
	} else {
		sliceArgs := make([]struct {
			SST int32
			SD  string
		}, 0, len(req.Slices))
		for _, s := range req.Slices {
			sliceArgs = append(sliceArgs, struct {
				SST int32
				SD  string
			}{SST: s.SST, SD: s.SD})
		}
		msg = ngap.BuildNGSetupRequestFromStore(req.MCC, req.MNC, req.TAC, req.GnbID, req.Name, req.SST, req.SD, sliceArgs)
	}

	encoded, err := ngap.Encode(msg)
	if err != nil {
		_ = t.Close()
		_ = h.Store.DeleteGnB(gnb.ID)
		delete(h.Transports, gnb.ID)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("ngap encode: %v", err))
		return
	}

	if err := t.Send(encoded, true); err != nil {
		_ = t.Close()
		_ = h.Store.DeleteGnB(gnb.ID)
		delete(h.Transports, gnb.ID)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sctp send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, "NGSetupResponse", "NGSetupFailure", "ErrorIndication")
	if err != nil {
		_ = t.Close()
		_ = h.Store.DeleteGnB(gnb.ID)
		delete(h.Transports, gnb.ID)
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for NGSetupResponse: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, CreateGnBResponse{
		GnBID:           gnb.ID,
		NGSetupResponse: ngapResp,
	})
}

func (h *Handler) GetGnB(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	gnb, err := h.Store.GetGnB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, GnBStateResponse{
		ID:    gnb.ID,
		MCC:   gnb.MCC,
		MNC:   gnb.MNC,
		TAC:   gnb.TAC,
		GnbID: gnb.GnbID,
		Name:  gnb.Name,
		SST:   gnb.SST,
		SD:    gnb.SD,
	})
}

func (h *Handler) DeleteGnB(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	if t, ok := h.Transports[gnbID]; ok {
		_ = t.Close()
		delete(h.Transports, gnbID)
	}

	if err := h.Store.DeleteGnB(gnbID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
