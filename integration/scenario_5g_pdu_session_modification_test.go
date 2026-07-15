// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// UE-requested PDU Session Modification (TS 23.502 §4.3.3.2, TS 24.501 §6.4.2).
// The UE cannot set its own QoS — authorized QoS is network-determined — so the
// network answers a PDU SESSION MODIFICATION REQUEST with a Modification Reject
// (§6.4.2.4).

package integration_test

import (
	"fmt"
	"testing"
)

func Test5GPDUSessionModification_Rejected(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID) // registered UE with an active PDU session

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_modification_request"}`)

	if status == 504 {
		t.Fatalf("got no response (HTTP 504); TS 24.501 §6.4.2.4 requires a Modification Reject\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapDownlinkNASTransport {
		t.Fatalf("modification response ngap.message_type = %q, want DownlinkNASTransport\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionModificationReject {
		t.Errorf("nas.inner_nas_message_type = %q, want pdu_session_modification_reject (TS 24.501 §6.4.2.4)\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.cause_5gsm"); got == "" {
		t.Errorf("Modification Reject missing its mandatory 5GSM cause IE (TS 24.501 §8.3.8)\n  body: %s", body)
	}
}

// With no PDU session context at the AMF there is nothing to forward the message
// to, so TS 24.501 §7.3.2 c) requires 5GMM cause #90 "payload was not forwarded".
func Test5GPDUSessionModification_NoActiveSession(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_modification_request"}`)

	if status == 504 {
		t.Fatalf("got no response (HTTP 504); TS 24.501 §7.3.2 c) requires a Downlink NAS Transport with 5GMM cause #90\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapDownlinkNASTransport {
		t.Fatalf("ngap.message_type = %q, want DownlinkNASTransport\n  body: %s", got, body)
	}

	assertNASCause(t, body, "nas.cause_5gmm", cause5GMMPayloadWasNotForwarded)
}

// Request Type "existing PDU session" must be forwarded to the SMF (TS 24.501
// §5.4.5.2.3 ii), which answers with a Modification Reject.
func Test5GPDUSessionModification_ExistingPduSessionRequestType(t *testing.T) {
	const requestTypeExistingPduSession = 2

	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	body := fmt.Sprintf(`{"message_type":"pdu_session_modification_request","request_type":%d}`, requestTypeExistingPduSession)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
	}

	if got := jsonGet(resp, "nas.inner_nas_message_type"); got != nasPDUSessionModificationReject {
		t.Errorf("nas.inner_nas_message_type = %q, want pdu_session_modification_reject (forwarded to SMF, TS 24.501 §5.4.5.2.3 ii)\n  body: %s", got, resp)
	}
}

// Ella Core supports no emergency PDU sessions, so Request Type "initial
// emergency request" has nothing to forward to and draws 5GMM cause #90.
func Test5GPDUSessionModification_EmergencyRequestType(t *testing.T) {
	const requestTypeInitialEmergency = 3

	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID)

	body := fmt.Sprintf(`{"message_type":"pdu_session_modification_request","request_type":%d}`, requestTypeInitialEmergency)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
	if status == 504 {
		t.Fatalf("got no response (HTTP 504) for an emergency request type\n  body: %s", resp)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
	}

	if got := jsonGet(resp, "ngap.message_type"); got != ngapDownlinkNASTransport {
		t.Fatalf("ngap.message_type = %q, want DownlinkNASTransport\n  body: %s", got, resp)
	}

	assertNASCause(t, resp, "nas.cause_5gmm", cause5GMMPayloadWasNotForwarded)
}
