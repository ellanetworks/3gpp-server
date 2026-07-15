// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// ESM STATUS handling (TS 24.301 §6.7): the MME must act on the cause of a
// received ESM STATUS and must not answer it with another STATUS.

package integration_test

import (
	"testing"
)

// Test4GESMStatus_InvalidBearerReleases sends an ESM STATUS #43 (invalid EPS
// bearer identity) for the default bearer: the MME must deactivate it locally,
// and deactivating the default bearer releases the UE (TS 24.301 §6.7, §6.4.4.2).
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

// Test4GESMStatus_SessionRemainsUsable sends a valid ESM STATUS: the MME must
// process it, leaving the UE usable, and must not answer with an ESM STATUS #97
// (TS 24.301 §6.7).
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
