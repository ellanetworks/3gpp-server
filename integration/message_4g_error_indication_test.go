// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// TS 36.413 §8.7.2 leaves the receiver's reaction implementation-specific, so
// only an Error Indication in return is failed.
func Test4GErrorIndicationAccepted(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"error_indication","timeout_ms":3000}`)
	if got := jsonGet(resp, "s1ap.message_type"); got == "ErrorIndication" {
		t.Fatalf("MME answered a valid Error Indication with an Error Indication (TS 36.413 §8.7.2)\n  body: %s", resp)
	}
}
