// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func Test4GInitialContextSetupFailure(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	if got := jsonGet(nasStep(t, enbID, ueID, "attach_request"), "nas.message_type"); got != "authentication_request" {
		t.Fatalf("attach_request: got %q", got)
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "authentication_response"), "nas.message_type"); got != "security_mode_command" {
		t.Fatalf("authentication_response: got %q", got)
	}

	smc := nasStep(t, enbID, ueID, "security_mode_complete")
	if got := jsonGet(smc, "s1ap.message_type"); got != "InitialContextSetupRequest" {
		t.Fatalf("security_mode_complete: s1ap.message_type = %q, want InitialContextSetupRequest\n  body: %s", got, smc)
	}

	nasStep(t, enbID, ueID, "initial_context_setup_failure")

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/nas",
		`{"message_type":"release_request","timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("release_request: HTTP %d\n  body: %s", status, resp)
	}

	if got := jsonGet(resp, "s1ap.message_type"); got == "UEContextReleaseCommand" {
		t.Fatalf("MME answered a release with a Release Command after an Initial Context Setup Failure — the context must already be released (TS 36.413 §8.3.1.4, TS 23.401 §5.3.2.1)\n  body: %s", resp)
	}

	fullAttach(t, enbID, mustCreateENBUE(t, enbID))
}
