// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// TS 24.501 §5.5.1.2.8: the AMF starts T3550 on sending the REGISTRATION ACCEPT
// and, on its expiry with no REGISTRATION COMPLETE, retransmits the accept. The
// twin of the 4G T3450 attach-accept retransmission.
func Test5GRegistrationAcceptRetransmission(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)

	if got := jsonGet(ngap5GStep(t, gnbID, ueID, "registration_request"), "nas.message_type"); got != nasAuthenticationRequest {
		t.Fatalf("registration_request: nas.message_type = %q, want authentication_request", got)
	}

	if got := jsonGet(ngap5GStep(t, gnbID, ueID, "authentication_response"), "nas.message_type"); got != nasSecurityModeCommand {
		t.Fatalf("authentication_response: nas.message_type = %q, want security_mode_command", got)
	}

	if got := jsonGet(ngap5GStep(t, gnbID, ueID, "security_mode_complete"), "nas.message_type"); got != nasRegistrationAccept {
		t.Fatalf("security_mode_complete: nas.message_type = %q, want registration_accept", got)
	}

	// T3550 defaults to 6 s; allow margin. Registration Complete is withheld.
	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":12000}`)
	if status != 200 {
		t.Fatalf("no Registration Accept retransmission after withholding Registration Complete (HTTP %d) — the T3550 guard must retransmit (TS 24.501 §5.5.1.2.8)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasRegistrationAccept {
		t.Fatalf("retransmitted NAS = %q, want registration_accept (TS 24.501 §5.5.1.2.8)\n  body: %s", got, body)
	}
}
