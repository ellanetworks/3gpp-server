// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"strconv"
	"testing"
)

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

	// TS 24.501 Table 9.11.4.16.1: values 4-6 are unused but interpretable, 0 and 7 reserved.
	switch sscMode := jsonGet(body, "nas.ssc_mode"); sscMode {
	case "":
		t.Errorf("Establishment Accept missing the mandatory Selected SSC mode IE (TS 24.501 Table 8.3.2.1.1)\n  body: %s", body)
	case "0", "7":
		t.Errorf("nas.ssc_mode = %q, want an assigned SSC mode value (TS 24.501 Table 9.11.4.16.1)\n  body: %s", sscMode, body)
	}

	pduSessionType := jsonGet(body, "nas.pdu_session_type")
	if pduSessionType == "" {
		t.Fatalf("Establishment Accept missing the mandatory Selected PDU session type IE (TS 24.501 Table 8.3.2.1.1)\n  body: %s", body)
	}

	// TS 24.501 §6.4.1.3: the SMF selects the PDU session type, but every IP type
	// obliges it to include the PDU address IE.
	switch pduSessionType {
	case strconv.Itoa(pduSessionTypeIPv4), strconv.Itoa(pduSessionTypeIPv6), strconv.Itoa(pduSessionTypeIPv4IPv6):
		if got := jsonGet(body, "nas.pdu_address"); got == "" {
			t.Errorf("Establishment Accept selected PDU session type %q but carries no PDU address IE (TS 24.501 §6.4.1.3)\n  body: %s", pduSessionType, body)
		}
	}
}

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

// TS 24.501 §6.4.1.3 b) ii): without an Always-on PDU session requested IE the SMF
// must not answer "not allowed". Case a) still permits "required", which is the
// SMF's own determination.
func Test5GPDUSessionEstablishment_AlwaysOnIndicationNotRequested(t *testing.T) {
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

	if got := jsonGet(body, "nas.always_on_indication"); got == strconv.Itoa(alwaysOnPDUSessionNotAllowed) {
		t.Errorf("UE sent no Always-on PDU session requested IE, but the Establishment Accept carries an Always-on PDU session indication set to \"not allowed\" (TS 24.501 §6.4.1.3 b) ii)\n  body: %s", body)
	}
}

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

	assertNASCause(t, resp, "nas.5gsm_cause", cause5GSMPTIMismatch)
}

// TS 24.501 §7.4 leaves the reaction to an unsolicited 5GSM STATUS to the
// implementation, so only the session surviving is asserted.
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
