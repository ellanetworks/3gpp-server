//go:build integration

// UE-requested PDU Session Modification (TS 23.502 §4.3.3.2, TS 24.501 §6.4.2).
// The UE sends a PDU SESSION MODIFICATION REQUEST on an active PDU session; per
// §6.4.2.3/§6.4.2.4 the network must answer with a PDU Session Modification
// Command (accepted) or a Modification Reject (not accepted) — or a 5GSM STATUS
// for a PTI error (§7.3.1). The only case where the network may stay silent is a
// reserved PTI (§7.3.1 d). Rejecting is compliant; silently dropping a valid
// request is not.

package integration_test

import (
	"testing"
)

// TestPDUSessionModification_Rejected reproduces the procedure on an active
// session. The UE cannot set its own QoS — authorized QoS is network-determined
// — so the network must answer with a PDU Session Modification Reject carrying a
// 5GSM cause (TS 24.501 §6.4.2.4), delivered in a Downlink NAS Transport. A
// timeout (no downlink) would mean the request was silently dropped, which is
// non-compliant.
func TestPDUSessionModification_Rejected(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID) // registered UE with an active PDU session

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_modification_request"}`)

	if status == 504 {
		t.Fatalf("no response to a UE-requested PDU Session Modification Request — TS 24.501 §6.4.2.4 requires a Modification Reject (silently dropping it is non-compliant)\n  body: %s", body)
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
// established one). The network must still respond — e.g. a 5GSM STATUS with
// cause #43 "invalid PDU session identity" (TS 24.501 §6.4.2.4 / §7.3) — rather
// than silently drop the request.
func TestPDUSessionModification_NoActiveSession(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_modification_request"}`)

	if status == 504 {
		t.Fatalf("no response to a PDU Session Modification Request for an inactive PDU session — TS 24.501 §6.4.2.4/§7.3 require a response (e.g. 5GSM STATUS cause #43); silently dropping it is non-compliant\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
}
