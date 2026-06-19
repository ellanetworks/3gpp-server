// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// fullAttach drives a UE all the way to EMM-REGISTERED, failing the test on any
// non-compliant step.
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

// TestEPSPreS1SetupGating checks the MME refuses a UE-associated procedure on an
// association that has not completed S1 Setup (TS 36.413 §8.7.1): it must not
// authenticate the UE.
func TestEPSPreS1SetupGating(t *testing.T) {
	body := `{
		"mme_address": "10.3.0.2:36412",
		"enb_s1_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "0001", "enb_id": 1,
		"name": "no-s1setup-enb",
		"skip_s1_setup": true
	}`

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create eNB (skip S1 Setup): HTTP %d: %s", status, resp)
	}

	enbID := jsonGet(resp, "enb_id")
	t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+enbID, "") })

	ueID := mustCreateENBUE(t, enbID)

	status, resp = doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/nas",
		`{"message_type":"attach_request","timeout_ms":1500}`)

	// The MME must not progress the attach. A silent drop (gateway timeout) or an
	// Error Indication is compliant; issuing an Authentication Request is not.
	if status == 200 && jsonGet(resp, "nas.message_type") == "authentication_request" {
		t.Fatalf("MME authenticated a UE before S1 Setup completed (TS 36.413 §8.7.1); body: %s", resp)
	}
}

// TestEPSForgedS1APIDInjection checks the MME does not act on a UE-associated NAS
// message that references an MME-UE-S1AP-ID it never assigned (a forged UE
// association, TS 36.413 §10.6), and stays healthy afterwards.
func TestEPSForgedS1APIDInjection(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	resp := nasBody(t, enbID, ueID,
		`{"message_type":"inject_nas","mme_ue_s1ap_id":4294967000,"raw_nas_pdu":"00","timeout_ms":1500}`)

	// The MME must not route this as a valid NAS exchange into any context. An
	// Error Indication or silence is acceptable; a Downlink NAS Transport is not.
	if got := jsonGet(resp, "s1ap.message_type"); got == "DownlinkNASTransport" {
		t.Fatalf("MME routed NAS for a forged MME-UE-S1AP-ID; body: %s", resp)
	}

	// The MME must remain healthy: a fresh UE still attaches.
	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// TestEPSNASReplay replays a UE's last protected uplink (its Attach Complete, at a
// now-stale NAS COUNT) and checks the MME discards it (TS 24.301 §4.4.3.5) without
// adverse effect, staying healthy.
func TestEPSNASReplay(t *testing.T) {
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
