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

	// A stale COUNT fails integrity verification (TS 24.301 §4.4.3.5), so §4.4.4.3
	// applies and the reply is a SERVICE REJECT, not a discard.
	resp := nasBody(t, enbID, ueID,
		`{"message_type":"service_request","nas_count":0,"timeout_ms":3000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-established on a Service Request with a stale NAS COUNT (TS 24.301 §4.4.3.5); body: %s", resp)
	}

	if got := jsonGet(resp, "nas.message_type"); got != "service_reject" {
		t.Fatalf("nas.message_type = %q, want service_reject (TS 24.301 §4.4.4.3); body: %s", got, resp)
	}

	if got := jsonGet(resp, "nas.emm_cause"); got != "9" {
		t.Errorf("service_reject nas.emm_cause = %q, want 9 (TS 24.301 §4.4.4.3); body: %s", got, resp)
	}
}
