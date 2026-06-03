//go:build integration

// 5GSM Procedure Transaction Identity error handling (TS 24.501 §7.3.1). The
// network must police the PTI of every 5GSM message it receives: respond with a
// 5GSM STATUS for a mismatched (#47) or unassigned (#81) PTI, and silently
// ignore a reserved PTI. A failing test means Ella Core does not enforce §7.3.1.

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

// TestPDUSessionReleaseComplete_PTIMismatch sends a PDU SESSION RELEASE COMPLETE
// carrying an assigned PTI on an active session for which the network started no
// release procedure, so the PTI matches none in use. Per TS 24.501 §7.3.1 a) the
// network shall respond with a 5GSM STATUS carrying cause #47 "PTI mismatch".
func TestPDUSessionReleaseComplete_PTIMismatch(t *testing.T) {
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

// TestPDUSessionEstablishment_UnassignedPTI sends a PDU SESSION ESTABLISHMENT
// REQUEST whose PTI is the unassigned value 0. Per TS 24.501 §7.3.1 c) the
// network shall respond with a 5GSM STATUS carrying cause #81 "invalid PTI
// value", not establish the session.
func TestPDUSessionEstablishment_UnassignedPTI(t *testing.T) {
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

// TestPDUSessionEstablishment_ReservedPTI sends a PDU SESSION ESTABLISHMENT
// REQUEST whose PTI is the reserved value 255. Per TS 24.501 §7.3.1 d) the
// network shall ignore the message: no response and no session. A response of
// any kind (an Establishment Accept, a Reject, or a Resource Setup) is a §7.3.1
// d) violation.
func TestPDUSessionEstablishment_ReservedPTI(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_establishment_request","pti":%d}`, ptiReserved))

	if status != 504 {
		t.Errorf("reserved-PTI Establishment Request must be ignored (TS 24.501 §7.3.1 d), but the network responded: HTTP %d\n  body: %s", status, body)
	}
}

// TestPDUSessionModificationRequest_UnassignedPTI sends a PDU SESSION
// MODIFICATION REQUEST on an active session with the unassigned PTI 0. The AMF
// forwards it to the SMF, which per TS 24.501 §7.3.1 c) answers with a 5GSM
// STATUS carrying cause #81 rather than a Modification Reject.
func TestPDUSessionModificationRequest_UnassignedPTI(t *testing.T) {
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

// TestPDUSessionReleaseRequest_UnassignedPTI sends a PDU SESSION RELEASE REQUEST
// with the unassigned PTI 0. Per TS 24.501 §7.3.1 c) the SMF answers with a 5GSM
// STATUS carrying cause #81 rather than releasing the session.
func TestPDUSessionReleaseRequest_UnassignedPTI(t *testing.T) {
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

// TestPDUSessionModificationRequest_ReservedPTI sends a PDU SESSION MODIFICATION
// REQUEST with the reserved PTI 255 on an active session. Per TS 24.501 §7.3.1
// d) the SMF ignores the message: the AMF forwards nothing back, so the request
// elicits no response.
func TestPDUSessionModificationRequest_ReservedPTI(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_modification_request","pti":%d}`, ptiReserved))

	if status != 504 {
		t.Errorf("reserved-PTI Modification Request must be ignored (TS 24.501 §7.3.1 d), but the network responded: HTTP %d\n  body: %s", status, body)
	}
}

// TestPDUSessionModificationComplete_PTIMismatch sends a PDU SESSION
// MODIFICATION COMPLETE carrying an assigned PTI for which the network started
// no modification procedure. Per TS 24.501 §7.3.1 a) the SMF answers with a 5GSM
// STATUS carrying cause #47 "PTI mismatch".
func TestPDUSessionModificationComplete_PTIMismatch(t *testing.T) {
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

// awaitUENGAP waits for an unsolicited downlink NGAP message addressed to the UE
// and returns the response body (NGAP plus any decoded NAS).
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
