package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiSpec []byte

func OpenAPISpec() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/openapi+yaml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(openapiSpec)
	})
}
