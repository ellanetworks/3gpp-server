package api

import "net/http"

func NewRouter(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /gnb", h.CreateGnB)
	mux.HandleFunc("GET /gnb/{gnb_id}", h.GetGnB)
	mux.HandleFunc("DELETE /gnb/{gnb_id}", h.DeleteGnB)

	return mux
}
