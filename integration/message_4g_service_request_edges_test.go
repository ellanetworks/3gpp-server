// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// The Initial UE Message carries no MME-UE-S1AP-ID, so the override never reaches the MME.
func Test4GServiceRequest_StaleMMEIDOverride(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	nasStep(t, enbID, ueID, "release_request")

	resp := nasBody(t, enbID, ueID,
		`{"message_type":"service_request","mme_ue_s1ap_id_override":99999,"timeout_ms":3000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "InitialContextSetupRequest" {
		t.Errorf("s1ap.message_type = %q, want InitialContextSetupRequest (re-establishment)\n  body: %s", got, resp)
	}
}

func Test4GServiceRequestStaleNASCount(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	nasStep(t, enbID, ueID, "release_request")

	if got := jsonGet(nasStep(t, enbID, ueID, "service_request"), "s1ap.message_type"); got != "InitialContextSetupRequest" {
		t.Fatalf("first service request did not re-establish: got %q", got)
	}

	nasStep(t, enbID, ueID, "release_request")

	// A stale NAS COUNT must not re-establish the UE-associated connection
	// (TS 24.301 §4.4.3.5). The MME's rejection is ciphered under a downlink
	// context that cannot be reconstructed once the count is forced backwards,
	// so only the non-re-establishment invariant is asserted.
	resp := nasBody(t, enbID, ueID,
		`{"message_type":"service_request","nas_count":0,"timeout_ms":3000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-established on a Service Request with a stale NAS COUNT (TS 24.301 §4.4.3.5); body: %s", resp)
	}
}
