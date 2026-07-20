// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// TS 38.413 §8.7.5 leaves the receiver's reaction implementation-specific, so
// only an Error Indication in return is failed.
func Test5GErrorIndicationAccepted(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"error_indication","timeout_ms":3000}`)
	if status == 200 {
		if got := jsonGet(body, "ngap.message_type"); got == ngapErrorIndication {
			t.Fatalf("AMF answered a valid Error Indication with an Error Indication (TS 38.413 §8.7.5)\n  body: %s", body)
		}
	}
}
