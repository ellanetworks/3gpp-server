package api

import "net/http"

func NewRouter(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("GET /openapi.yaml", OpenAPISpec())

	mux.HandleFunc("POST /gnb", h.CreateGnB)
	mux.HandleFunc("GET /gnb/{gnb_id}", h.GetGnB)
	mux.HandleFunc("DELETE /gnb/{gnb_id}", h.DeleteGnB)

	mux.HandleFunc("POST /gnb/{gnb_id}/ngap", h.SendGnBNGAP)

	mux.HandleFunc("POST /gnb/{gnb_id}/ue", h.CreateUE)
	mux.HandleFunc("GET /gnb/{gnb_id}/ue/{ue_id}", h.GetUE)
	mux.HandleFunc("PATCH /gnb/{gnb_id}/ue/{ue_id}", h.PatchUE)
	mux.HandleFunc("DELETE /gnb/{gnb_id}/ue/{ue_id}", h.DeleteUE)

	mux.HandleFunc("POST /gnb/{gnb_id}/ue/{ue_id}/ngap", h.SendNGAP)

	return mux
}
