// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// waitTimeout is how long a send or await blocks for its downlink: the request's
// timeout_ms when set, otherwise 5s.
func waitTimeout(timeoutMs int) time.Duration {
	if timeoutMs > 0 {
		return time.Duration(timeoutMs) * time.Millisecond
	}

	return 5 * time.Second
}

// parsedAwaitRequest is an AwaitRequest with its timeout resolved.
type parsedAwaitRequest struct {
	MessageTypes []string
	timeout      time.Duration
}

func decodeAwaitRequest(w http.ResponseWriter, r *http.Request) (parsedAwaitRequest, bool) {
	var req AwaitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return parsedAwaitRequest{}, false
	}

	if len(req.MessageTypes) == 0 {
		writeError(w, http.StatusBadRequest, "message_types is required")
		return parsedAwaitRequest{}, false
	}

	return parsedAwaitRequest{MessageTypes: req.MessageTypes, timeout: waitTimeout(req.TimeoutMs)}, true
}
