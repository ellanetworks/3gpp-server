// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type PatchENBUERequest struct {
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
		ue.MMEIDKnown = true
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

type ENBTunnelResponse struct {
	EBI    uint8  `json:"ebi"`
	APN    string `json:"apn,omitempty"`
	UEIP   string `json:"ue_ip,omitempty"`
	ULTeid uint32 `json:"ul_teid,omitempty"`
	UPFIP  string `json:"upf_ip,omitempty"`
	DLTeid uint32 `json:"dl_teid,omitempty"`
}

func (h *Handler) GetENBTunnel(w http.ResponseWriter, r *http.Request) {
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

	ebi := uint8(0)

	if v := r.URL.Query().Get("ebi"); v != "" {
		n, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid ebi: %v", err))
			return
		}

		ebi = uint8(n)
	}

	ulTeid, dlTeid, upfIP, ueIP, found := enbBearer(ue, ebi)
	if !found {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("no user-plane tunnel for bearer %d; complete an attach / pdn_connectivity on a GTP-U-enabled eNB", ebi))
		return
	}

	resp := ENBTunnelResponse{EBI: ebi, UEIP: ueIP, ULTeid: ulTeid, UPFIP: upfIP, DLTeid: dlTeid}
	if ebi == 0 || ebi == ue.EPSBearerID {
		resp.EBI = ue.EPSBearerID
	} else if b, exists := ue.Bearers[ebi]; exists {
		resp.APN = b.APN
	}

	writeJSON(w, http.StatusOK, resp)
}
