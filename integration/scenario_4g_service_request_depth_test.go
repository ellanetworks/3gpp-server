// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// Test4GServiceRequestAfterDetach sends a Service Request from a detached UE:
// its EMM context is deregistered, so the MME must reject it (Service Reject,
// TS 24.301 §5.6.1.5) and must not re-establish the bearer.
func Test4GServiceRequestAfterDetach(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	nasStep(t, enbID, ueID, "detach_request")

	sr := nasBody(t, enbID, ueID, `{"message_type":"service_request","timeout_ms":3000}`)

	if got := jsonGet(sr, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-established a detached UE via Service Request (TS 24.301 §5.6.1.5); body: %s", sr)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// Test4GServiceRequestWhileConnected sends a Service Request from an
// already-connected UE. It carries a fresh Initial UE Message, so the MME may
// treat it as a new S1 connection and re-establish the context (TS 24.301 §5.6.1)
// or reject it; either way service must survive.
func Test4GServiceRequestWhileConnected(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	sr := nasBody(t, enbID, ueID, `{"message_type":"service_request","timeout_ms":3000}`)

	switch got := jsonGet(sr, "s1ap.message_type"); got {
	case "InitialContextSetupRequest", "DownlinkNASTransport", "":
		// Re-established, rejected, or ignored — all conformant.
	default:
		t.Fatalf("service request while connected: unexpected s1ap.message_type %q; body: %s", got, sr)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// Test4GServiceRequestBackToBack sends two Service Requests in succession after
// an idle release: the first re-establishes the connection, the second arrives on
// the freshly-connected UE (TS 24.301 §5.6.1).
func Test4GServiceRequestBackToBack(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	if got := jsonGet(nasStep(t, enbID, ueID, "release_request"), "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("release: s1ap.message_type = %q, want UEContextReleaseCommand", got)
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "service_request"), "s1ap.message_type"); got != "InitialContextSetupRequest" {
		t.Fatalf("first service request: s1ap.message_type = %q, want InitialContextSetupRequest (re-establishment)", got)
	}

	second := nasBody(t, enbID, ueID, `{"message_type":"service_request","timeout_ms":3000}`)
	switch got := jsonGet(second, "s1ap.message_type"); got {
	case "InitialContextSetupRequest", "DownlinkNASTransport", "":
		// Re-established, rejected, or ignored — all conformant.
	default:
		t.Fatalf("second service request: unexpected s1ap.message_type %q; body: %s", got, second)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
