// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func fullAttach(t *testing.T, enbID, ueID string) {
	t.Helper()

	if got := jsonGet(nasStep(t, enbID, ueID, "attach_request"), "nas.message_type"); got != "authentication_request" {
		t.Fatalf("attach_request: got %q", got)
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "authentication_response"), "nas.message_type"); got != "security_mode_command" {
		t.Fatalf("authentication_response: got %q", got)
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "security_mode_complete"), "nas.message_type"); got != "attach_accept" {
		t.Fatalf("security_mode_complete: got %q", got)
	}

	nasStep(t, enbID, ueID, "attach_complete")
}

func Test4GPreS1SetupGating(t *testing.T) {
	body := fmt.Sprintf(`{
		"mme_address": "10.3.0.2:36412",
		"enb_s1_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "0001", "enb_id": "%x",
		"name": "no-s1setup-enb",
		"skip_s1_setup": true
	}`, claimENBID())

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create eNB (skip S1 Setup): HTTP %d: %s", status, resp)
	}

	enbID := jsonGet(resp, "enb_id")
	t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+enbID, "") })

	ueID := mustCreateENBUE(t, enbID)

	status, resp = doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		`{"message_type":"attach_request","timeout_ms":1500}`)

	// TS 36.413 §8.7.1 leaves a drop and an Error Indication both compliant.
	if status == 200 && jsonGet(resp, "nas.message_type") == "authentication_request" {
		t.Fatalf("MME authenticated a UE before S1 Setup completed (TS 36.413 §8.7.1); body: %s", resp)
	}
}

func Test4GForgedS1APIDInjection(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	resp := nasBody(t, enbID, ueID,
		`{"message_type":"inject_nas","mme_ue_s1ap_id_override":4294967000,"raw_nas_pdu":"00","timeout_ms":1500}`)

	// TS 36.413 §10.6 leaves silence and an Error Indication both compliant.
	if got := jsonGet(resp, "s1ap.message_type"); got == "DownlinkNASTransport" {
		t.Fatalf("MME routed NAS for a forged MME-UE-S1AP-ID; body: %s", resp)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

func Test4GNASReplay(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID,
		`{"message_type":"inject_nas","replay_last":true,"timeout_ms":1500}`)

	if got := jsonGet(resp, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME re-processed a replayed protected NAS message (TS 24.301 §4.4.3.5); body: %s", resp)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
