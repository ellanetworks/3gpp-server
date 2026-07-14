// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// Test5GErrorIndicationReleasesUE checks that a UE-associated ERROR INDICATION
// from the gNB makes the AMF release the UE (TS 38.413 §8.7.5).
func Test5GErrorIndicationReleasesUE(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"error_indication"}`)
	if status != 200 {
		t.Fatalf("error_indication: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Fatalf("ngap.message_type = %q, want UEContextReleaseCommand (TS 38.413 §8.7.5)\n  body: %s", got, body)
	}
}
