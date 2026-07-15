// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func attachChallenge(t *testing.T, enbID string) string {
	t.Helper()

	ueID := mustCreateENBUE(t, enbID)

	resp := nasStep(t, enbID, ueID, "attach_request")
	if got := jsonGet(resp, "nas.message_type"); got != "authentication_request" {
		t.Fatalf("attach_request: nas.message_type = %q, want authentication_request; body: %s", got, resp)
	}

	return ueID
}

func nasBody(t *testing.T, enbID, ueID, body string) []byte {
	t.Helper()

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/nas", body)
	if status != 200 {
		t.Fatalf("nas step: HTTP %d: %s", status, resp)
	}

	return resp
}

// Test4GAuthenticationWrongRES checks a UE returning an incorrect RES draws an
// Authentication Reject (TS 24.301 §5.4.2.5).
func Test4GAuthenticationWrongRES(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := attachChallenge(t, enbID)

	resp := nasBody(t, enbID, ueID,
		`{"message_type":"authentication_response","res_override":"0000000000000000"}`)

	if got := jsonGet(resp, "nas.message_type"); got != "authentication_reject" {
		t.Fatalf("nas.message_type = %q, want authentication_reject; body: %s", got, resp)
	}
}

// Test4GAuthenticationFailureNoProceed checks an Authentication Failure (#20 MAC
// failure or #26 non-EPS) does not lead to security activation. Per TS 24.301
// §5.4.2.7 c/d the MME may run the identity procedure or send an Authentication
// Reject; either is compliant, a Security Mode Command is not.
func Test4GAuthenticationFailureNoProceed(t *testing.T) {
	tests := []struct {
		name  string
		cause int
	}{
		{"MAC failure #20", 20},
		{"non-EPS unacceptable #26", 26},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID := attachChallenge(t, enbID)

			resp := nasBody(t, enbID, ueID,
				fmt.Sprintf(`{"message_type":"authentication_failure","cause":%d}`, tt.cause))

			got := jsonGet(resp, "nas.message_type")
			if got == "security_mode_command" {
				t.Fatalf("MME activated security after an Authentication Failure #%d; body: %s", tt.cause, resp)
			}

			if got != "authentication_reject" && got != "identity_request" {
				t.Fatalf("nas.message_type = %q, want authentication_reject or identity_request; body: %s", got, resp)
			}
		})
	}
}

// Test4GAuthenticationSynchFailure checks the MME handles a #21 synch failure by
// re-synchronising with the HSS and re-challenging with a fresh vector
// (TS 24.301 §5.4.2.7 e), after which the attach can complete.
func Test4GAuthenticationSynchFailure(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := attachChallenge(t, enbID)

	resync := nasBody(t, enbID, ueID,
		`{"message_type":"authentication_failure","cause":21}`)

	if got := jsonGet(resync, "nas.message_type"); got != "authentication_request" {
		t.Fatalf("after synch failure, nas.message_type = %q, want a fresh authentication_request; body: %s", got, resync)
	}

	// Reaching the Security Mode Command proves the re-sync produced a usable vector.
	smc := nasStep(t, enbID, ueID, "authentication_response")
	if got := jsonGet(smc, "nas.message_type"); got != "security_mode_command" {
		t.Fatalf("after re-sync, nas.message_type = %q, want security_mode_command; body: %s", got, smc)
	}

	if got := jsonGet(smc, "mac_verified"); got != "true" {
		t.Fatalf("re-sync Security Mode Command NAS-MAC did not verify; body: %s", smc)
	}
}
