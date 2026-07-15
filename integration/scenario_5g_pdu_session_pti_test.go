// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// 5GSM Procedure Transaction Identity error handling (TS 24.501 §7.3.1): the
// network must police the PTI of every 5GSM message it receives, responding with
// a 5GSM STATUS for a mismatched (#47) or unassigned (#81) PTI, and ignoring a
// reserved PTI.

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

const (
	ptiUnassigned uint8 = 0   // "no procedure transaction identity assigned" (TS 24.501 §9.6)
	ptiReserved   uint8 = 255 // reserved value (TS 24.501 §9.6)
)

// The network started no release procedure, so the assigned PTI matches none in
// use and §7.3.1 a) requires a 5GSM STATUS with cause #47 "PTI mismatch".
func Test5GPDUSessionReleaseComplete_PTIMismatch(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_complete","pti":5}`)
	if status != 200 {
		t.Fatalf("pdu_session_release_complete: HTTP %d\n  body: %s", status, body)
	}

	resp := awaitUENGAP(t, gnbID, ueID, ngapDownlinkNASTransport)

	if got := jsonGet(resp, "nas.inner_nas_message_type"); got != nas5GSMStatus {
		t.Errorf("nas.inner_nas_message_type = %q, want 5gsm_status (TS 24.501 §7.3.1 a)\n  body: %s", got, resp)
	}

	assertNASCause(t, resp, "nas.cause_5gsm", cause5GSMPTIMismatch)
}

// On the unassigned PTI, §7.3.1 c) requires a 5GSM STATUS with cause #81 "invalid
// PTI value" and no session.
func Test5GPDUSessionEstablishment_UnassignedPTI(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_establishment_request","pti":%d}`, ptiUnassigned))
	if status == 504 {
		t.Fatalf("no response to an unassigned-PTI Establishment Request; TS 24.501 §7.3.1 c) requires a 5GSM STATUS with cause #81\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapDownlinkNASTransport {
		t.Errorf("ngap.message_type = %q, want DownlinkNASTransport carrying a 5GSM STATUS (TS 24.501 §7.3.1 c)\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nas5GSMStatus {
		t.Errorf("nas.inner_nas_message_type = %q, want 5gsm_status (TS 24.501 §7.3.1 c)\n  body: %s", got, body)
	}

	assertNASCause(t, body, "nas.cause_5gsm", cause5GSMInvalidPTIValue)
}

// On the reserved PTI, §7.3.1 d) requires the network to ignore the message, so
// the expected outcome is a timeout and a response of any kind is a violation.
func Test5GPDUSessionEstablishment_ReservedPTI(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_establishment_request","pti":%d}`, ptiReserved))

	if status != 504 {
		t.Errorf("reserved-PTI Establishment Request must be ignored (TS 24.501 §7.3.1 d), but the network responded: HTTP %d\n  body: %s", status, body)
	}
}

// The PTI check precedes the modification outcome: §7.3.1 c) requires a 5GSM
// STATUS with cause #81, so a Modification Reject is not conformant here.
func Test5GPDUSessionModificationRequest_UnassignedPTI(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_modification_request","pti":%d}`, ptiUnassigned))
	if status == 504 {
		t.Fatalf("no response to an unassigned-PTI Modification Request; TS 24.501 §7.3.1 c) requires a 5GSM STATUS with cause #81\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nas5GSMStatus {
		t.Errorf("nas.inner_nas_message_type = %q, want 5gsm_status (TS 24.501 §7.3.1 c)\n  body: %s", got, body)
	}

	assertNASCause(t, body, "nas.cause_5gsm", cause5GSMInvalidPTIValue)
}

// The PTI check precedes the release: §7.3.1 c) requires a 5GSM STATUS with cause
// #81 and the session must survive.
func Test5GPDUSessionReleaseRequest_UnassignedPTI(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_release_request","pti":%d}`, ptiUnassigned))
	if status == 504 {
		t.Fatalf("no response to an unassigned-PTI Release Request; TS 24.501 §7.3.1 c) requires a 5GSM STATUS with cause #81\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nas5GSMStatus {
		t.Errorf("nas.inner_nas_message_type = %q, want 5gsm_status (TS 24.501 §7.3.1 c)\n  body: %s", got, body)
	}

	assertNASCause(t, body, "nas.cause_5gsm", cause5GSMInvalidPTIValue)
}

// On the reserved PTI, §7.3.1 d) requires the SMF to ignore the message, so the
// expected outcome is a timeout.
func Test5GPDUSessionModificationRequest_ReservedPTI(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_modification_request","pti":%d}`, ptiReserved))

	if status != 504 {
		t.Errorf("reserved-PTI Modification Request must be ignored (TS 24.501 §7.3.1 d), but the network responded: HTTP %d\n  body: %s", status, body)
	}
}

// The network started no modification procedure, so §7.3.1 a) requires a 5GSM
// STATUS with cause #47 "PTI mismatch".
func Test5GPDUSessionModificationComplete_PTIMismatch(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_modification_complete","pti":6}`)
	if status != 200 {
		t.Fatalf("pdu_session_modification_complete: HTTP %d\n  body: %s", status, body)
	}

	resp := awaitUENGAP(t, gnbID, ueID, ngapDownlinkNASTransport)

	if got := jsonGet(resp, "nas.inner_nas_message_type"); got != nas5GSMStatus {
		t.Errorf("nas.inner_nas_message_type = %q, want 5gsm_status (TS 24.501 §7.3.1 a)\n  body: %s", got, resp)
	}

	assertNASCause(t, resp, "nas.cause_5gsm", cause5GSMPTIMismatch)
}

func awaitUENGAP(t *testing.T, gnbID, ueID string, messageTypes ...string) []byte {
	t.Helper()

	mt, _ := json.Marshal(messageTypes)
	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/await",
		fmt.Sprintf(`{"message_types": %s, "timeout_ms": 5000}`, mt))
	if status != 200 {
		t.Fatalf("await %v on ue %s: HTTP %d\n  body: %s", messageTypes, ueID, status, body)
	}

	return body
}
