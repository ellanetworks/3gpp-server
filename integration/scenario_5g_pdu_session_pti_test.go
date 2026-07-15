// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TS 24.501 §9.6.
const (
	ptiUnassigned uint8 = 0
	ptiReserved   uint8 = 255
)

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

func Test5GPDUSessionModificationRequest_ReservedPTI(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_modification_request","pti":%d}`, ptiReserved))

	if status != 504 {
		t.Errorf("reserved-PTI Modification Request must be ignored (TS 24.501 §7.3.1 d), but the network responded: HTTP %d\n  body: %s", status, body)
	}
}

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
