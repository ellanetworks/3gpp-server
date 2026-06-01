//go:build integration

// UE-requested PDU session release (TS 24.501 §6.3.3): the UE sends a PDU
// Session Release Request; the SMF answers with a Release Command (inside an
// NGAP PDU Session Resource Release Command); the UE confirms with a Release
// Complete.

package integration_test

import "testing"

// TestPDUSessionRelease_UERequested establishes a PDU session, then releases it
// on the UE's initiative and confirms with a Release Complete.
func TestPDUSessionRelease_UERequested(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("pdu_session_establishment_request: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_request"}`)
	if status != 200 {
		t.Fatalf("pdu_session_release_request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapPDUSessionResourceReleaseCommand {
		t.Errorf("ngap.message_type = %q, want PDUSessionResourceReleaseCommand\n  body: %s", got, body)
	}
	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionReleaseCommand {
		t.Errorf("nas.inner_nas_message_type = %q, want pdu_session_release_command (TS 24.501 §6.3.3)\n  body: %s", got, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_complete"}`)
	if status != 200 {
		t.Fatalf("pdu_session_release_complete: HTTP %d\n  body: %s", status, body)
	}
}
