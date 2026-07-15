// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// 5GSM coverage beyond the PTI rules: Establishment Accept mandatory-IE content
// (TS 24.501 §8.3.2), the Always-on PDU session indication (§6.4.1), and the
// remaining UE-originated 5GSM messages (Modification Command Reject, 5GSM
// STATUS). Expectations are anchored in the spec; a failing test is an Ella Core
// non-compliance.

package integration_test

import (
	"testing"
)

// Test5GPDUSessionEstablishment_AcceptMandatoryIEs drives a successful
// establishment and asserts the Accept carries its mandatory IEs (TS 24.501
// §8.3.2): a Session-AMBR with non-zero up/downlink rates and a non-empty
// Authorized QoS rules IE.
func Test5GPDUSessionEstablishment_AcceptMandatoryIEs(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentAccept {
		t.Fatalf("nas.inner_nas_message_type = %q, want pdu_session_establishment_accept\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.session_ambr_uplink"); got == "" || got == "0" {
		t.Errorf("Establishment Accept missing a non-zero Session-AMBR uplink (TS 24.501 §8.3.2): %q\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.session_ambr_downlink"); got == "" || got == "0" {
		t.Errorf("Establishment Accept missing a non-zero Session-AMBR downlink (TS 24.501 §8.3.2): %q\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.authorized_qos_rules"); got == "" {
		t.Errorf("Establishment Accept missing the mandatory Authorized QoS rules IE (TS 24.501 §8.3.2)\n  body: %s", body)
	}
}

// Test5GPDUSessionEstablishment_AlwaysOnIndication establishes a session whose
// request carries the Always-on PDU session requested IE. Per TS 24.501 §6.4.1
// (case b-i) the SMF shall include an Always-on PDU session indication in the
// Establishment Accept (set to "required" or "not allowed") whenever the UE
// requested one.
func Test5GPDUSessionEstablishment_AlwaysOnIndication(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request","always_on_requested":true}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentAccept {
		t.Fatalf("nas.inner_nas_message_type = %q, want pdu_session_establishment_accept\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.always_on_indication"); got == "" {
		t.Errorf("UE requested an always-on PDU session; TS 24.501 §6.4.1 (case b-i) requires an Always-on PDU session indication in the Establishment Accept, but none was present\n  body: %s", body)
	}
}

// Test5GPDUSessionModificationCommandReject_PTIMismatch sends a PDU SESSION
// MODIFICATION COMMAND REJECT carrying a PTI for which the network started no
// modification procedure. Per TS 24.501 §7.3.1 a) the SMF answers with a 5GSM
// STATUS carrying cause #47 "PTI mismatch".
func Test5GPDUSessionModificationCommandReject_PTIMismatch(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_modification_command_reject","pti":8}`)
	if status != 200 {
		t.Fatalf("pdu_session_modification_command_reject: HTTP %d\n  body: %s", status, body)
	}

	resp := awaitUENGAP(t, gnbID, ueID, ngapDownlinkNASTransport)

	if got := jsonGet(resp, "nas.inner_nas_message_type"); got != nas5GSMStatus {
		t.Errorf("nas.inner_nas_message_type = %q, want 5gsm_status (TS 24.501 §7.3.1 a)\n  body: %s", got, resp)
	}

	assertNASCause(t, resp, "nas.cause_5gsm", cause5GSMPTIMismatch)
}

// Test5GStatus5GSM_FromUE_SessionRemainsUsable sends a 5GSM STATUS to the SMF for
// an active session. TS 24.501 §7.4 leaves the network's reaction to an
// unsolicited 5GSM STATUS implementation-dependent, so no specific response is
// required; the session must remain intact, which is shown by a subsequent
// UE-requested release succeeding.
func Test5GStatus5GSM_FromUE_SessionRemainsUsable(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"status_5gsm","pti":3}`)
	if status != 200 {
		t.Fatalf("status_5gsm: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_request"}`)
	if status != 200 {
		t.Fatalf("release after 5GSM STATUS: HTTP %d, want 200 (session must survive an unsolicited STATUS)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionReleaseCommand {
		t.Errorf("release after 5GSM STATUS: nas.inner_nas_message_type = %q, want pdu_session_release_command (the session must remain usable)\n  body: %s", got, body)
	}
}
