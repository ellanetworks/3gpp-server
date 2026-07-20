// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
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

var defaultNGSetupWait = []string{"NGSetupResponse", "NGSetupFailure", "ErrorIndication"}

func (h *Handler) CreateGNB(w http.ResponseWriter, r *http.Request) {
	var req CreateGNBRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.AMFAddress == "" {
		writeError(w, http.StatusBadRequest, "amf_address is required")
		return
	}

	localAddr := req.GNBN2Address
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

	gnb := h.Store.CreateGNB(req.MCC, req.MNC, req.TAC, req.GNBID, req.GNBIDBitLen, req.Name, req.SST, req.SD, slices)
	gnb.N3Addr = localAddr
	h.Transports[gnb.ID] = t

	if req.EnableGTPU {
		n3 := req.GNBN3Address
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
		writeJSON(w, http.StatusCreated, CreateGNBResponse{GNBID: gnb.ID})
		return
	}

	var encoded []byte

	if req.RawNGAPPDU != nil {
		decoded, derr := hex.DecodeString(*req.RawNGAPPDU)
		if derr != nil {
			h.teardownGNB(gnb.ID, t)
			writeError(w, http.StatusBadRequest, fmt.Sprintf("raw_ngap_pdu must be hex: %v", derr))
			return
		}

		encoded = decoded
	} else {
		var msg *ngap.NGAPMessage
		if len(req.NGSetupIEs) > 0 {
			msg = &ngap.NGAPMessage{
				ProcedureCode: ngapType.ProcedureCodeNGSetup,
				PDUType:       "initiating_message",
				Criticality:   "reject",
				IEs:           req.NGSetupIEs,
			}
		} else {
			sliceArgs := make([]ngap.NGSetupSlice, 0, len(req.Slices))
			for _, s := range req.Slices {
				sliceArgs = append(sliceArgs, ngap.NGSetupSlice{SST: s.SST, SD: s.SD})
			}
			var berr error
			msg, berr = ngap.BuildNGSetupRequestFromStore(ngap.NGSetupRequestFromStoreParams{
				MCC:              req.MCC,
				MNC:              req.MNC,
				TAC:              req.TAC,
				GNBID:            req.GNBID,
				GNBIDBitLen:      req.GNBIDBitLen,
				Name:             req.Name,
				SST:              req.SST,
				SD:               req.SD,
				Slices:           sliceArgs,
				DefaultPagingDRX: req.DefaultPagingDRX,
			})
			if berr != nil {
				h.teardownGNB(gnb.ID, t)
				writeError(w, http.StatusBadRequest, fmt.Sprintf("build ng setup: %v", berr))
				return
			}
		}

		var eerr error
		encoded, eerr = ngap.Encode(msg)
		if eerr != nil {
			h.teardownGNB(gnb.ID, t)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("ngap encode: %v", eerr))
			return
		}
	}

	if err := t.Send(encoded, true); err != nil {
		h.teardownGNB(gnb.ID, t)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sctp send: %v", err))
		return
	}

	waitFor := req.WaitFor
	if len(waitFor) == 0 {
		waitFor = defaultNGSetupWait
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, waitFor...)
	if err != nil {
		h.teardownGNB(gnb.ID, t)
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for NGSetupResponse: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, CreateGNBResponse{
		GNBID:           gnb.ID,
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

	writeJSON(w, http.StatusOK, GNBStateResponse{
		ID:          gnb.ID,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GNBID:       gnb.GNBID,
		GNBIDBitLen: gnb.GNBIDBitLen,
		Name:        gnb.Name,
		SST:         gnb.SST,
		SD:          gnb.SD,
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
