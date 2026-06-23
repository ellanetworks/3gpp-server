// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// TestEPSServiceRequestAfterDetach checks a detached UE cannot re-establish its
// connection with a Service Request: the EMM context is no longer registered, so
// the MME must reject it (Service Reject, TS 24.301 §5.6.1.5) and must not
// re-establish the bearer.
func Test4GServiceRequestAfterDetach(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	nasStep(t, enbID, ueID, "detach_request")

	sr := nasBody(t, enbID, ueID, `{"message_type":"service_request","timeout_ms":3000}`)

	if got := jsonGet(sr, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-established a detached UE via Service Request (TS 24.301 §5.6.1.5); body: %s", sr)
	}

	// The MME must remain healthy: a fresh UE still attaches.
	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// TestEPSServiceRequestWhileConnected checks a Service Request from an
// already-connected UE does not crash the MME: it carries a fresh Initial UE
// Message, so the MME treats it as a new S1 connection and re-establishes the
// context (TS 24.301 §5.6.1) — or rejects it — without disrupting service.
func Test4GServiceRequestWhileConnected(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	sr := nasBody(t, enbID, ueID, `{"message_type":"service_request","timeout_ms":3000}`)

	switch got := jsonGet(sr, "s1ap.message_type"); got {
	case "InitialContextSetupRequest", "DownlinkNASTransport", "":
		// Re-established, rejected, or ignored — all valid; the MME stays up.
	default:
		t.Fatalf("service request while connected: unexpected s1ap.message_type %q; body: %s", got, sr)
	}

	// The MME must remain healthy: a fresh UE still attaches.
	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// TestEPSServiceRequestBackToBack checks two Service Requests in succession after
// an idle release do not crash the MME: the first re-establishes the connection,
// the second arrives on the freshly-connected UE (TS 24.301 §5.6.1).
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
		// Any of these is acceptable; the MME must not crash.
	default:
		t.Fatalf("second service request: unexpected s1ap.message_type %q; body: %s", got, second)
	}

	// The MME must remain healthy: a fresh UE still attaches.
	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
