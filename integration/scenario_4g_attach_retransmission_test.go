// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// Test4GAttachAcceptRetransmission withholds the Attach Complete: the MME's
// T3450 guard must retransmit the Attach Accept (TS 24.301 §5.6.2).
func Test4GAttachAcceptRetransmission(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	if got := jsonGet(nasStep(t, enbID, ueID, "attach_request"), "nas.message_type"); got != "authentication_request" {
		t.Fatalf("attach_request: nas.message_type = %q, want authentication_request", got)
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "authentication_response"), "nas.message_type"); got != "security_mode_command" {
		t.Fatalf("authentication_response: nas.message_type = %q, want security_mode_command", got)
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "security_mode_complete"), "nas.message_type"); got != "attach_accept" {
		t.Fatalf("security_mode_complete: nas.message_type = %q, want attach_accept", got)
	}

	// T3450 defaults to 6 s; allow margin for the retransmission to arrive.
	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":12000}`)
	if status != 200 {
		t.Fatalf("no Attach Accept retransmission after withholding Attach Complete (HTTP %d) — the T3450 guard must retransmit (TS 24.301 §5.6.2)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != "attach_accept" {
		t.Fatalf("retransmitted NAS = %q, want attach_accept (TS 24.301 §5.6.2)\n  body: %s", got, body)
	}
}
