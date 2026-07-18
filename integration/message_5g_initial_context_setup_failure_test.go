// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func ngap5GStep(t *testing.T, gnbID, ueID, messageType string) []byte {
	t.Helper()

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"`+messageType+`"}`)
	if status != 200 {
		t.Fatalf("%s: HTTP %d\n  body: %s", messageType, status, resp)
	}

	return resp
}

func Test5GInitialContextSetupFailure(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	if got := jsonGet(ngap5GStep(t, gnbID, ueID, "registration_request"), "nas.message_type"); got != nasAuthenticationRequest {
		t.Fatalf("registration_request: nas.message_type = %q, want authentication_request", got)
	}

	if got := jsonGet(ngap5GStep(t, gnbID, ueID, "authentication_response"), "nas.message_type"); got != nasSecurityModeCommand {
		t.Fatalf("authentication_response: nas.message_type = %q, want security_mode_command", got)
	}

	smc := ngap5GStep(t, gnbID, ueID, "security_mode_complete")
	if got := jsonGet(smc, "ngap.message_type"); got != ngapInitialContextSetupRequest {
		t.Fatalf("security_mode_complete: ngap.message_type = %q, want InitialContextSetupRequest\n  body: %s", got, smc)
	}

	ngap5GStep(t, gnbID, ueID, "initial_context_setup_failure")

	_, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request","timeout_ms":3000}`)

	if got := jsonGet(resp, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Fatalf("after Initial Context Setup Failure the NG-connection persists; a UE Context Release Request must be answered with a UE Context Release Command (TS 38.413 §8.3.2.2), got %q\n  body: %s", got, resp)
	}

	doRegistrationFlow(t, gnbID, mustCreateUE(t, gnbID))
}
