//go:build integration

// UE-requested PDU session release (TS 24.501 §6.3.3): the UE sends a PDU
// Session Release Request; the SMF answers with a Release Command (inside an
// NGAP PDU Session Resource Release Command); the UE confirms with a Release
// Complete.

package integration_test

import "testing"

// establishedPDUSession registers a UE and establishes its PDU session,
// returning the gNB/UE IDs.
func establishedPDUSession(t *testing.T) (string, string) {
	t.Helper()

	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("pdu_session_establishment_request: HTTP %d\n  body: %s", status, body)
	}

	return gnbID, ueID
}

// TestPDUSessionRelease_UERequested releases an established session on the UE's
// initiative and confirms with a Release Complete.
func TestPDUSessionRelease_UERequested(t *testing.T) {
	gnbID, ueID := establishedPDUSession(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
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

// TestPDUSessionRelease_ThenReestablish confirms the release actually tore the
// session down: a fresh PDU Session Establishment Request afterwards succeeds.
func TestPDUSessionRelease_ThenReestablish(t *testing.T) {
	gnbID, ueID := establishedPDUSession(t)

	for _, step := range []string{"pdu_session_release_request", "pdu_session_release_complete"} {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"`+step+`"}`)
		if status != 200 {
			t.Fatalf("%s: HTTP %d\n  body: %s", step, status, body)
		}
	}

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("re-establish: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapPDUSessionResourceSetupRequest {
		t.Errorf("ngap.message_type = %q, want PDUSessionResourceSetupRequest\n  body: %s", got, body)
	}
	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentAccept {
		t.Errorf("nas.inner_nas_message_type = %q, want pdu_session_establishment_accept\n  body: %s", got, body)
	}
}

// TestPDUSessionRelease_Fuzz sends a malformed inner SM payload in the Release
// Request. The AMF must answer, never silently drop (no 504).
func TestPDUSessionRelease_Fuzz(t *testing.T) {
	gnbID, ueID := establishedPDUSession(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_request","raw_nas_pdu":"deadbeef"}`)
	if status == 504 {
		t.Fatalf("release request hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasStatus5GMM {
		t.Errorf("nas.message_type = %q, want status_5gmm\n  body: %s", got, body)
	}
	assertNASCause(t, body, "nas.cause_5gmm", cause5GMMProtocolErrorUnspecified)
}

// TestPDUSessionRelease_NGAPIDFuzz forges the AMF UE NGAP ID on the Release
// Request's Uplink NAS Transport. The AMF does not recognise the ID and answers
// with an Error Indication (TS 38.413 §8.6.3), never silently dropping it.
func TestPDUSessionRelease_NGAPIDFuzz(t *testing.T) {
	gnbID, ueID := establishedPDUSession(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_request","amf_ue_ngap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("release request hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("ngap.message_type = %q, want ErrorIndication\n  body: %s", got, body)
	}
}
