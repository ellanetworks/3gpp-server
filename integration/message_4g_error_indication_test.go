// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// Test4GErrorIndicationAccepted checks the MME accepts a UE-associated ERROR
// INDICATION from the eNB. TS 36.413 §8.7.2 defines only the reporting procedure;
// the receiver's reaction is implementation-specific (Ella Core releases the UE),
// so the only spec-grounded assertion is that the MME does not answer a valid
// Error Indication with an Error Indication of its own.
func Test4GErrorIndicationAccepted(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"error_indication","timeout_ms":3000}`)
	if got := jsonGet(resp, "s1ap.message_type"); got == "ErrorIndication" {
		t.Fatalf("MME answered a valid Error Indication with an Error Indication (TS 36.413 §8.7.2)\n  body: %s", resp)
	}
}
