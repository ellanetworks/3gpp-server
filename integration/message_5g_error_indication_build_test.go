// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// Test5GErrorIndicationAccepted checks the AMF accepts a UE-associated ERROR
// INDICATION from the gNB. TS 38.413 §8.7.5 defines only the reporting procedure
// and message content; the receiver's reaction is implementation-specific (Ella
// Core releases the UE), so the only spec-grounded assertion is that the AMF does
// not answer a valid Error Indication with an Error Indication of its own.
func Test5GErrorIndicationAccepted(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"error_indication","timeout_ms":3000}`)
	if status == 200 {
		if got := jsonGet(body, "ngap.message_type"); got == ngapErrorIndication {
			t.Fatalf("AMF answered a valid Error Indication with an Error Indication (TS 38.413 §8.7.5)\n  body: %s", body)
		}
	}
}
