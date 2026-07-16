// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func Test4GServiceRequestUnknownUE(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	nasStep(t, enbID, ueID, "release_request")

	resp := nasBody(t, enbID, ueID, `{"message_type":"service_request","mtmsi":305419896,"timeout_ms":3000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-established for an unknown S-TMSI; body: %s", resp)
	}

	if got := jsonGet(resp, "nas.message_type"); got != "service_reject" {
		t.Fatalf("unknown-S-TMSI service request: nas.message_type = %q, want service_reject; body: %s", got, resp)
	}

	if got := jsonGet(resp, "nas.emm_cause"); got != "9" {
		t.Errorf("unknown-S-TMSI service_reject: nas.emm_cause = %q, want 9 (TS 24.301 §4.4.4.3); body: %s", got, resp)
	}
}

func Test4GServiceRequestReplay(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	nasStep(t, enbID, ueID, "release_request")

	if got := jsonGet(nasStep(t, enbID, ueID, "service_request"), "s1ap.message_type"); got != "InitialContextSetupRequest" {
		t.Fatalf("first service request did not re-establish: got %q", got)
	}

	nasStep(t, enbID, ueID, "release_request")

	resp := nasBody(t, enbID, ueID, `{"message_type":"service_request","nas_count":0,"timeout_ms":3000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-established on a Service Request with a stale NAS COUNT (TS 24.301 §4.4.3.5); body: %s", resp)
	}
}
