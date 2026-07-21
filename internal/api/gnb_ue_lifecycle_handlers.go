// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type PatchGNBUERequest struct {
	K           *string `json:"k,omitempty"`
	OPc         *string `json:"opc,omitempty"`
	AMF         *string `json:"amf,omitempty"`
	SQN         *string `json:"sqn,omitempty"`
	AMFUENGAPID *int64  `json:"amf_ue_ngap_id,omitempty"`
	DNN         *string `json:"dnn,omitempty"`
	SST         *int32  `json:"sst,omitempty"`
	SD          *string `json:"sd,omitempty"`
	IMEISV      *string `json:"imeisv,omitempty"`
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
	if req.AMF != nil {
		ue.AMF = *req.AMF
	}
	if req.SQN != nil {
		ue.SQN = *req.SQN
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
