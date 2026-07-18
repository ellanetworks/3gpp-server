// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"strconv"
	"testing"
)

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

	const releasePTI = 7

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_release_request","pti":%d}`, releasePTI))
	if status != 200 {
		t.Fatalf("pdu_session_release_request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapPDUSessionResourceReleaseCommand {
		t.Errorf("ngap.message_type = %q, want PDUSessionResourceReleaseCommand\n  body: %s", got, body)
	}
	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionReleaseCommand {
		t.Fatalf("nas.inner_nas_message_type = %q, want pdu_session_release_command (TS 24.501 §6.3.3)\n  body: %s", got, body)
	}

	// TS 24.501 §6.3.3.2: a release triggered by a UE-requested release echoes the
	// request's PTI and carries no Access type IE.
	if got := jsonGet(body, "nas.pti"); got != strconv.Itoa(releasePTI) {
		t.Errorf("nas.pti = %q, want %d — the Release Command must echo the Release Request's PTI (TS 24.501 §6.3.3.2)\n  body: %s", got, releasePTI, body)
	}

	if got := jsonGet(body, "nas.access_type_present"); got != "false" {
		t.Errorf("nas.access_type_present = %q, want false — a UE-triggered Release Command must omit the Access type IE (TS 24.501 §6.3.3.2)\n  body: %s", got, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_release_complete","pti":%d}`, releasePTI))
	if status != 200 {
		t.Fatalf("pdu_session_release_complete: HTTP %d\n  body: %s", status, body)
	}
}

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
