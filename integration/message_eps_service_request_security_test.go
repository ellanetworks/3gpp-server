// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// TestEPSServiceRequestUnknownUE checks the MME refuses a Service Request whose
// S-TMSI it never assigned: it must not re-establish, and replies with a Service
// Reject (TS 24.301 §5.6.1.5).
func TestEPSServiceRequestUnknownUE(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	nasStep(t, enbID, ueID, "release_request")

	// M-TMSI 0x12345678 was never allocated by the MME.
	resp := nasBody(t, enbID, ueID, `{"message_type":"service_request","mtmsi":305419896,"timeout_ms":3000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-established for an unknown S-TMSI; body: %s", resp)
	}

	if got := jsonGet(resp, "nas.message_type"); got != "service_reject" {
		t.Fatalf("unknown-S-TMSI service request: nas.message_type = %q, want service_reject; body: %s", got, resp)
	}
}

// TestEPSServiceRequestReplay checks the MME refuses a Service Request carrying a
// stale uplink NAS COUNT (a replay): it must not re-establish the connection
// (TS 24.301 §4.4.3.5).
func TestEPSServiceRequestReplay(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	nasStep(t, enbID, ueID, "release_request")

	if got := jsonGet(nasStep(t, enbID, ueID, "service_request"), "s1ap.message_type"); got != "InitialContextSetupRequest" {
		t.Fatalf("first service request did not re-establish: got %q", got)
	}

	nasStep(t, enbID, ueID, "release_request")

	// Replay with a stale NAS COUNT (0): below the MME's current expected count.
	resp := nasBody(t, enbID, ueID, `{"message_type":"service_request","nas_count":0,"timeout_ms":3000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-established on a Service Request with a stale NAS COUNT (TS 24.301 §4.4.3.5); body: %s", resp)
	}
}
