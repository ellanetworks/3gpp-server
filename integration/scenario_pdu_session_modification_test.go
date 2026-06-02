//go:build integration

// UE-requested PDU Session Modification (TS 23.502 §4.3.3.2, TS 24.501 §6.4.2).
// The UE cannot set its own QoS — authorized QoS is network-determined — so the
// network answers a PDU SESSION MODIFICATION REQUEST with a Modification Reject
// (§6.4.2.4).

package integration_test

import (
	"testing"
)

// TestPDUSessionModification_Rejected drives the procedure on an active session
// and asserts a PDU Session Modification Reject with a 5GSM cause (TS 24.501
// §6.4.2.4), delivered in a Downlink NAS Transport.
func TestPDUSessionModification_Rejected(t *testing.T) {
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

	assertNASCause(t, body, "nas.cause_5gsm", cause5GSMRequestRejectedUnspecified)
}

// TestPDUSessionModification_NoActiveSession sends a Modification Request for a
// PDU session that has no active context (the UE is registered but never
// established one). The network responds with a rejection — e.g. a 5GSM STATUS
// with cause #43 "invalid PDU session identity" (TS 24.501 §6.4.2.4 / §7.3).
func TestPDUSessionModification_NoActiveSession(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_modification_request"}`)

	if status == 504 {
		t.Fatalf("got no response (HTTP 504); TS 24.501 §6.4.2.4/§7.3 require a response (e.g. 5GSM STATUS cause #43)\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
}
