// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type PatchENBUERequest struct {
	IMEISV      *string `json:"imeisv,omitempty"`
	K           *string `json:"k,omitempty"`
	OPc         *string `json:"opc,omitempty"`
	AMF         *string `json:"amf,omitempty"`
	SQN         *string `json:"sqn,omitempty"`
	MMEUES1APID *uint32 `json:"mme_ue_s1ap_id,omitempty"`
}

func (h *Handler) PatchENBUE(w http.ResponseWriter, r *http.Request) {
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

	var req PatchENBUERequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.IMEISV != nil {
		ue.IMEISV = *req.IMEISV
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

	if req.MMEUES1APID != nil {
		ue.MMEUES1APID = *req.MMEUES1APID
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) DeleteENBUE(w http.ResponseWriter, r *http.Request) {
	enb, err := h.Store.GetENB(r.PathValue("enb_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	if !enb.DeleteUE(r.PathValue("ue_id")) {
		writeError(w, http.StatusNotFound, "ue not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
