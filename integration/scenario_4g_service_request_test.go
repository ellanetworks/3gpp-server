// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// Test4GServiceRequest drives the idle/connected cycle: an S1 release to
// ECM-IDLE, then a Service Request that re-establishes the bearer (TS 24.301
// §5.6.1).
func Test4GServiceRequest(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	idle := nasStep(t, enbID, ueID, "release_request")
	if got := jsonGet(idle, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("release_request: s1ap.message_type = %q, want UEContextReleaseCommand; body: %s", got, idle)
	}

	sr := nasStep(t, enbID, ueID, "service_request")
	if got := jsonGet(sr, "s1ap.message_type"); got != "InitialContextSetupRequest" {
		t.Fatalf("service_request: s1ap.message_type = %q, want InitialContextSetupRequest (re-establishment); body: %s", got, sr)
	}
}

// Test4GServiceRequestBadMAC sends a Service Request whose short-MAC does not
// verify: the MME must refuse to re-establish the connection (TS 24.301 §5.6.1.5).
func Test4GServiceRequestBadMAC(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	nasStep(t, enbID, ueID, "release_request")

	sr := nasBody(t, enbID, ueID, `{"message_type":"service_request","corrupt_mac":true,"timeout_ms":3000}`)

	if got := jsonGet(sr, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-established on a Service Request with an invalid short-MAC (TS 24.301 §5.6.1.5); body: %s", sr)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
