// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// UE-requested PDU session release (TS 24.501 §6.3.3): the UE sends a PDU
// Session Release Request; the SMF answers with a Release Command (inside an
// NGAP PDU Session Resource Release Command); the UE confirms with a Release
// Complete.

package integration_test

import "testing"

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

func Test5GPDUSessionRelease_UERequested(t *testing.T) {
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

// A succeeding re-establishment is what proves the release freed the session's
// state.
func Test5GPDUSessionRelease_ThenReestablish(t *testing.T) {
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

// A forged AMF UE NGAP ID on the Uplink NAS Transport is an unknown local AP ID,
// so the AMF shall initiate an Error Indication procedure (TS 38.413 §10.6).
func Test5GPDUSessionRelease_NGAPIDFuzz(t *testing.T) {
	gnbID, ueID := establishedPDUSession(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_request","amf_ue_ngap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("release request hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	assertSpecCompliantErrorIndication(t, body)
}
