// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/transport"
)

type errorResponse struct {
	Error string `json:"error"`
}

type statusError struct {
	status int
	err    error
}

func (e *statusError) Error() string { return e.err.Error() }
func (e *statusError) Unwrap() error { return e.err }

func httpErrorf(status int, format string, args ...any) error {
	return &statusError{status: status, err: fmt.Errorf(format, args...)}
}

func statusForError(err error) int {
	var se *statusError
	if errors.As(err, &se) {
		return se.status
	}

	switch {
	case errors.Is(err, transport.ErrTimeout):
		return http.StatusGatewayTimeout
	case errors.Is(err, transport.ErrSend):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
