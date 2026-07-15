// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import "net/http"

func NewRouter(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("GET /openapi.yaml", OpenAPISpec())

	mux.HandleFunc("POST /gnb", h.CreateGNB)
	mux.HandleFunc("GET /gnb/{gnb_id}", h.GetGNB)
	mux.HandleFunc("DELETE /gnb/{gnb_id}", h.DeleteGNB)

	// 4G/LTE: eNB lifecycle over S1-MME (S1AP).
	mux.HandleFunc("POST /enb", h.CreateENB)
	mux.HandleFunc("GET /enb/{enb_id}", h.GetENB)
	mux.HandleFunc("DELETE /enb/{enb_id}", h.DeleteENB)

	// 4G/LTE: UE lifecycle and EPS NAS procedures over S1AP.
	mux.HandleFunc("POST /enb/{enb_id}/ue", h.CreateENBUE)
	mux.HandleFunc("GET /enb/{enb_id}/ue/{ue_id}", h.GetENBUE)
	mux.HandleFunc("PATCH /enb/{enb_id}/ue/{ue_id}", h.PatchENBUE)
	mux.HandleFunc("DELETE /enb/{enb_id}/ue/{ue_id}", h.DeleteENBUE)
	mux.HandleFunc("GET /enb/{enb_id}/ue/{ue_id}/tunnel", h.GetENBTunnel)
	mux.HandleFunc("POST /enb/{enb_id}/ue/{ue_id}/nas", h.SendENBNAS)
	mux.HandleFunc("POST /enb/{enb_id}/ue/{ue_id}/migrate", h.MigrateENBUE)

	// 4G/LTE: non-UE-associated S1AP send — the target-eNB side of S1 handover.
	mux.HandleFunc("POST /enb/{enb_id}/s1ap", h.SendENBS1AP)

	// 4G/LTE: await unsolicited MME-initiated S1AP downlink. The non-UE form
	// catches a Paging or MME-initiated Reset; the per-UE form catches a
	// network-initiated Detach Request or EPS bearer modification.
	mux.HandleFunc("POST /enb/{enb_id}/await", h.AwaitENBMessage)
	mux.HandleFunc("POST /enb/{enb_id}/ue/{ue_id}/await", h.AwaitENBUEMessage)

	// 4G/LTE: S1-U user plane (requires the eNB created with enable_gtpu).
	mux.HandleFunc("POST /enb/{enb_id}/ue/{ue_id}/uplink", h.SendENBUplink)
	mux.HandleFunc("POST /enb/{enb_id}/ue/{ue_id}/downlink/await", h.AwaitENBDownlink)
	mux.HandleFunc("POST /enb/{enb_id}/gtpu/echo", h.SendENBGTPUEcho)
	mux.HandleFunc("POST /enb/{enb_id}/gtpu/error-indication/await", h.AwaitENBErrorIndication)

	mux.HandleFunc("POST /gnb/{gnb_id}/ngap", h.SendGnBNGAP)
	mux.HandleFunc("POST /gnb/{gnb_id}/await", h.AwaitGnBMessage)

	mux.HandleFunc("POST /gnb/{gnb_id}/ue", h.CreateUE)
	mux.HandleFunc("GET /gnb/{gnb_id}/ue/{ue_id}", h.GetUE)
	mux.HandleFunc("PATCH /gnb/{gnb_id}/ue/{ue_id}", h.PatchUE)
	mux.HandleFunc("DELETE /gnb/{gnb_id}/ue/{ue_id}", h.DeleteUE)

	mux.HandleFunc("POST /gnb/{gnb_id}/ue/{ue_id}/migrate", h.MigrateUE)
	mux.HandleFunc("POST /gnb/{gnb_id}/ue/{ue_id}/ngap", h.SendNGAP)
	mux.HandleFunc("POST /gnb/{gnb_id}/ue/{ue_id}/await", h.AwaitUEMessage)

	// N3 / GTP-U data plane (requires the gNB to be created with enable_gtpu).
	mux.HandleFunc("POST /gnb/{gnb_id}/gtpu/echo", h.SendGTPUEcho)
	mux.HandleFunc("POST /gnb/{gnb_id}/gtpu/error-indication/await", h.AwaitErrorIndication)
	mux.HandleFunc("GET /gnb/{gnb_id}/ue/{ue_id}/tunnel", h.GetTunnel)
	mux.HandleFunc("POST /gnb/{gnb_id}/ue/{ue_id}/uplink", h.SendUplink)
	mux.HandleFunc("POST /gnb/{gnb_id}/ue/{ue_id}/downlink/await", h.AwaitDownlink)

	return mux
}
