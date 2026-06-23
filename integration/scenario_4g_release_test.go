// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// TestEPSUEContextRelease drives a normal eNB-initiated S1 release of a
// connected UE: the MME answers the UE Context Release Request with a UE Context
// Release Command carrying a Cause IE (TS 36.413 §9.1.4.6).
func Test4GUEContextRelease(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasStep(t, enbID, ueID, "release_request")

	if got := jsonGet(resp, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("release: s1ap.message_type = %q, want UEContextReleaseCommand; body: %s", got, resp)
	}

	if g := jsonGet(resp, "s1ap.cause.group"); g == "" {
		t.Fatalf("Release Command missing mandatory Cause IE (TS 36.413 §9.2.1.3); body: %s", resp)
	}
}

// TestEPSUEContextReleaseCommandEchoesCause checks the MME's Release Command
// reports the radio-network Cause the eNB requested (TS 36.413 §9.1.4.6).
func Test4GUEContextReleaseCommandEchoesCause(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	// 21 = radio-network "radio-connection-with-UE-lost" (TS 36.413 §9.2.1.3).
	resp := nasBody(t, enbID, ueID, `{"message_type":"release_request","release_cause":21}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("release: s1ap.message_type = %q, want UEContextReleaseCommand; body: %s", got, resp)
	}

	if g, v := jsonGet(resp, "s1ap.cause.group"), jsonGet(resp, "s1ap.cause.value"); g != "radio_network" || v != "21" {
		t.Fatalf("Release Command cause = %s/%s, want radio_network/21; body: %s", g, v, resp)
	}
}

// TestEPSUEContextReleaseBeforeContext checks the MME rejects a UE Context
// Release Request that arrives before any UE context exists (an MME-UE-S1AP-ID
// it never allocated): per TS 36.413 §10.6 it answers with an Error Indication,
// never a Release Command for a non-existent UE.
func Test4GUEContextReleaseBeforeContext(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"release_request","timeout_ms":3000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got == "UEContextReleaseCommand" {
		t.Fatalf("MME issued a Release Command before any UE context existed; body: %s", resp)
	}

	assertEPSErrorIndication(t, resp)
}

// TestEPSUEContextReleaseDoubleRelease checks a second release of an
// already-released UE is rejected: the first release moves the UE to ECM-IDLE
// (the S1 context and MME-UE-S1AP-ID are gone), so the repeat names an unknown
// logical connection and the MME answers with an Error Indication (TS 36.413
// §10.6) — it must not crash nor release a second time.
func Test4GUEContextReleaseDoubleRelease(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	first := nasStep(t, enbID, ueID, "release_request")
	if got := jsonGet(first, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("first release: s1ap.message_type = %q, want UEContextReleaseCommand; body: %s", got, first)
	}

	second := nasBody(t, enbID, ueID, `{"message_type":"release_request","timeout_ms":3000}`)
	if got := jsonGet(second, "s1ap.message_type"); got == "UEContextReleaseCommand" {
		t.Fatalf("MME released an already-released UE a second time; body: %s", second)
	}

	assertEPSErrorIndication(t, second)

	// The MME must remain healthy: a fresh UE still attaches.
	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
