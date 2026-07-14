// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// ESM STATUS handling (TS 24.301 §6.7): the MME must process a received ESM
// STATUS rather than answer it with another STATUS, and act on its cause. A
// failure of these tests means Ella Core deviates.

package integration_test

import (
	"testing"
)

// Test4GESMStatus_InvalidBearerReleases checks that an ESM STATUS #43 (invalid
// EPS bearer identity) for the default bearer makes the MME deactivate it
// locally; deactivating the default bearer releases the UE (TS 24.301 §6.7,
// §6.4.4.2).
func Test4GESMStatus_InvalidBearerReleases(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	nasBody(t, enbID, ueID, `{"message_type":"status_esm","esm_cause":43}`)

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["UEContextReleaseCommand"],"timeout_ms":5000}`)
	if status != 200 {
		t.Fatalf("await UEContextReleaseCommand: HTTP %d — the MME must locally deactivate the bearer on ESM STATUS #43 (TS 24.301 §6.7)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("s1ap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}
}

// Test4GESMStatus_SessionRemainsUsable checks that a valid ESM STATUS is not
// answered with an ESM STATUS #97 (TS 24.301 §6.7): the MME processes it and the
// UE stays usable.
func Test4GESMStatus_SessionRemainsUsable(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	nasBody(t, enbID, ueID, `{"message_type":"status_esm","esm_cause":111}`)

	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":1500}`); s == 200 {
		if got := jsonGet(b, "nas.message_type"); got == "esm_status" {
			t.Fatalf("the MME answered a valid ESM STATUS with an ESM STATUS (must process, not reply, TS 24.301 §6.7)\n  body: %s", b)
		}
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "release_request"), "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("UE not usable after sending ESM STATUS; release_request did not yield a UEContextReleaseCommand")
	}
}
