// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

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

func Test4GServiceRequestWhileConnected(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	sr := nasBody(t, enbID, ueID, `{"message_type":"service_request","timeout_ms":3000}`)

	switch got := jsonGet(sr, "s1ap.message_type"); got {
	case "InitialContextSetupRequest", "DownlinkNASTransport", "":
		// Re-establishing, rejecting and ignoring are all conformant (TS 24.301 §5.6.1).
	default:
		t.Fatalf("service request while connected: unexpected s1ap.message_type %q; body: %s", got, sr)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

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
		// Re-establishing, rejecting and ignoring are all conformant (TS 24.301 §5.6.1).
	default:
		t.Fatalf("second service request: unexpected s1ap.message_type %q; body: %s", got, second)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
