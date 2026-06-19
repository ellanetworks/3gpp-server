// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// TestScenarioDetach drives a UE-originating normal Detach after a full attach
// and asserts the MME replies with a Detach Accept (TS 24.301 §5.5.2.2.2).
func TestScenarioDetach(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasStep(t, enbID, ueID, "detach_request")
	if got := jsonGet(resp, "nas.message_type"); got != "detach_accept" {
		t.Fatalf("detach: nas.message_type = %q, want detach_accept (TS 24.301 §5.5.2.2.2); body: %s", got, resp)
	}
}

// TestEPSDetachSwitchOff drives a switch-off Detach and asserts the MME does NOT
// send a Detach Accept (TS 24.301 §5.5.2.2.2) and instead releases the S1
// connection, then stays healthy.
func TestEPSDetachSwitchOff(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"detach_request","switch_off":true}`)

	if got := jsonGet(resp, "nas.message_type"); got == "detach_accept" {
		t.Fatalf("MME sent a Detach Accept for a switch-off detach (TS 24.301 §5.5.2.2.2); body: %s", resp)
	}

	if got := jsonGet(resp, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("switch-off detach: s1ap.message_type = %q, want UEContextReleaseCommand; body: %s", got, resp)
	}

	fresh := createENBUEWithIMSI(t, enbID, testSUPI(2)[len("imsi-"):])
	fullAttach(t, enbID, fresh)
}
