// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// When a UE re-establishes on a new NG connection while an old one is still up, the AMF
// must release the superseded connection toward the gNB with a UE CONTEXT RELEASE
// COMMAND (TS 38.413 §8.3.2), not silently drop it.
func Test5GSupersededConnectionReleased(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request","registration_type":2,"reestablish":true,"timeout_ms":8000}`)
	if status != 200 {
		t.Fatalf("reestablish registration: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("superseded NG connection: ngap.message_type = %q, want UEContextReleaseCommand (TS 38.413 §8.3.2)\n  body: %s", got, body)
	}

	assertGNBCoreAlive(t)
}
