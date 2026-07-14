// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// Test4GErrorIndicationReleasesUE checks that a UE-associated ERROR INDICATION
// from the eNB makes the MME release the UE (TS 36.413 §8.6.1).
func Test4GErrorIndicationReleasesUE(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"error_indication","timeout_ms":5000}`)
	if got := jsonGet(resp, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("s1ap.message_type = %q, want UEContextReleaseCommand (TS 36.413 §8.6.1)\n  body: %s", got, resp)
	}
}
