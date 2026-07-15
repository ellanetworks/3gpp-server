// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

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
