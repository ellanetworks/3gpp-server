// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/gtpu"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
	"github.com/free5gc/ngap/ngapType"
)

type Handler struct {
	Store          *store.Store
	Transports     map[string]*transport.NGAPTransport
	GTPU           map[string]*gtpu.Endpoint
	S1APTransports map[string]*transport.S1APTransport
}

func NewHandler(s *store.Store) *Handler {
	return &Handler{
		Store:          s,
		Transports:     make(map[string]*transport.NGAPTransport),
		GTPU:           make(map[string]*gtpu.Endpoint),
		S1APTransports: make(map[string]*transport.S1APTransport),
	}
}

func (h *Handler) CreateGNB(w http.ResponseWriter, r *http.Request) {
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

	t, err := transport.DialNGAP(localAddr, req.AMFAddress)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sctp dial failed: %v", err))
		return
	}

	slices := make([]store.SliceConfig, 0, len(req.Slices))
	for _, s := range req.Slices {
		slices = append(slices, store.SliceConfig{SST: s.SST, SD: s.SD})
	}

	gnb := h.Store.CreateGNB(req.MCC, req.MNC, req.TAC, req.GnbID, req.Name, req.SST, req.SD, slices)
	gnb.N3Addr = localAddr
	h.Transports[gnb.ID] = t

	if req.EnableGTPU {
		n3 := req.GnBN3Address
		if n3 == "" {
			n3 = localAddr
		}

		gt, err := gtpu.Listen(n3)
		if err != nil {
			h.teardownGNB(gnb.ID, t)
			writeError(w, http.StatusBadGateway, fmt.Sprintf("gtp-u listen on %s failed: %v", n3, err))
			return
		}

		gnb.N3Addr = n3
		h.GTPU[gnb.ID] = gt
	}

	if req.SkipNGSetup {
		writeJSON(w, http.StatusCreated, CreateGnBResponse{GnBID: gnb.ID})
		return
	}

	var msg *ngap.NGAPMessage
	if len(req.NGSetupIEs) > 0 {
		msg = &ngap.NGAPMessage{
			ProcedureCode: ngapType.ProcedureCodeNGSetup,
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
		var berr error
		msg, berr = ngap.BuildNGSetupRequestFromStore(req.MCC, req.MNC, req.TAC, req.GnbID, req.Name, req.SST, req.SD, sliceArgs)
		if berr != nil {
			h.teardownGNB(gnb.ID, t)
			writeError(w, http.StatusBadRequest, fmt.Sprintf("build ng setup: %v", berr))
			return
		}
	}

	encoded, err := ngap.Encode(msg)
	if err != nil {
		h.teardownGNB(gnb.ID, t)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("ngap encode: %v", err))
		return
	}

	if err := t.Send(encoded, true); err != nil {
		h.teardownGNB(gnb.ID, t)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sctp send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(0))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, "NGSetupResponse", "NGSetupFailure", "ErrorIndication")
	if err != nil {
		h.teardownGNB(gnb.ID, t)
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for NGSetupResponse: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, CreateGnBResponse{
		GnBID:           gnb.ID,
		NGSetupResponse: ngapResp,
	})
}

func (h *Handler) GetGNB(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	gnb, err := h.Store.GetGNB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, GnBStateResponse{
		ID:    gnb.ID,
		MCC:   gnb.MCC,
		MNC:   gnb.MNC,
		TAC:   gnb.TAC,
		GnbID: gnb.GNBID,
		Name:  gnb.Name,
		SST:   gnb.SST,
		SD:    gnb.SD,
	})
}

func (h *Handler) DeleteGNB(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	if t, ok := h.Transports[gnbID]; ok {
		_ = t.Close()
		delete(h.Transports, gnbID)
	}

	if gt, ok := h.GTPU[gnbID]; ok {
		_ = gt.Close()
		delete(h.GTPU, gnbID)
	}

	if err := h.Store.DeleteGNB(gnbID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) teardownGNB(id string, t *transport.NGAPTransport) {
	_ = t.Close()

	if gt, ok := h.GTPU[id]; ok {
		_ = gt.Close()
		delete(h.GTPU, id)
	}

	_ = h.Store.DeleteGNB(id)
	delete(h.Transports, id)
}
