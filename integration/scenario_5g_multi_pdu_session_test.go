// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func establishNumberedPDUSession(t *testing.T, gnbID, ueID string, sessionID int) []byte {
	t.Helper()

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_establishment_request","pdu_session_id":%d}`, sessionID))
	if status != 200 {
		t.Fatalf("establish PDU session %d: HTTP %d\n  body: %s", sessionID, status, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentAccept {
		t.Fatalf("establish PDU session %d: inner = %q, want pdu_session_establishment_accept\n  body: %s", sessionID, got, body)
	}

	return body
}

func Test5GMultiPDUSessionEstablish(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	first := establishNumberedPDUSession(t, gnbID, ueID, 1)
	second := establishNumberedPDUSession(t, gnbID, ueID, 2)

	if got := jsonGet(second, "ngap.message_type"); got != ngapPDUSessionResourceSetupRequest {
		t.Errorf("second session ngap.message_type = %q, want PDUSessionResourceSetupRequest\n  body: %s", got, second)
	}

	ip1 := jsonGet(first, "nas.pdu_address")
	ip2 := jsonGet(second, "nas.pdu_address")

	if ip1 == "" || ip2 == "" {
		t.Fatalf("a PDU Session Establishment Accept is missing its PDU address (session1=%q session2=%q)", ip1, ip2)
	}

	// Each PDU session has its own IP address (TS 23.501 §5.8.2.2), so two concurrent
	// sessions must not share one.
	if ip1 == ip2 {
		t.Errorf("two concurrent PDU sessions share the address %s — separate sessions require separate addresses (TS 23.501 §5.8.2.2)", ip1)
	}

	if id := jsonGet(second, "nas.pdu_session_id"); id != "2" {
		t.Errorf("second session nas.pdu_session_id = %q, want 2 — the Accept must echo the requested PDU session identity\n  body: %s", id, second)
	}
}

func Test5GMultiPDUSessionReleaseOne(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	establishNumberedPDUSession(t, gnbID, ueID, 1)
	establishNumberedPDUSession(t, gnbID, ueID, 2)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_request"}`)
	if status != 200 {
		t.Fatalf("pdu_session_release_request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapPDUSessionResourceReleaseCommand {
		t.Errorf("release ngap.message_type = %q, want PDUSessionResourceReleaseCommand\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionReleaseCommand {
		t.Fatalf("release nas.inner_nas_message_type = %q, want pdu_session_release_command (TS 24.501 §6.3.3)\n  body: %s", got, body)
	}

	if status, cmp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_complete"}`); status != 200 {
		t.Fatalf("pdu_session_release_complete: HTTP %d\n  body: %s", status, cmp)
	}

	// Re-establishing the released session proves the UE is still usable after one of
	// its sessions was torn down.
	establishNumberedPDUSession(t, gnbID, ueID, 1)
}
