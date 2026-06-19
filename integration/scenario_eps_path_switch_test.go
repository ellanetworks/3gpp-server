// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"strings"
	"testing"
)

// TestEPSPathSwitch drives an X2-handover PATH SWITCH REQUEST after attach and
// asserts the MME acknowledges it with a fresh key-chain {NH, NCC} (TS 36.413
// §9.1.5.8, TS 33.401 §7.2.8). The MME seeds NCC=1 at Initial Context Setup and
// increases it by one per path switch (§7.2.8.4), so the first switch returns
// NCC=2 with a 256-bit NH.
func TestEPSPathSwitch(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasStep(t, enbID, ueID, "path_switch")

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestAcknowledge" {
		t.Fatalf("path switch: s1ap.message_type = %q, want PathSwitchRequestAcknowledge; body: %s", got, resp)
	}

	if got := jsonGet(resp, "s1ap.security_context.next_hop_chaining_count"); got != "2" {
		t.Fatalf("path switch ack NCC = %q, want 2 (TS 33.401 §7.2.8.4); body: %s", got, resp)
	}

	nh := jsonGet(resp, "s1ap.security_context.next_hop")
	if len(nh) != 64 {
		t.Fatalf("path switch ack NH = %q, want a 256-bit (64-hex) Next Hop; body: %s", nh, resp)
	}

	if nh == strings.Repeat("0", 64) {
		t.Fatalf("path switch ack NH is all-zero, not a derived key (TS 33.401 §7.2.8); body: %s", resp)
	}
}

// TestEPSPathSwitchNCCIncrements checks the MME advances the {NH, NCC} chain on
// every path switch: the NCC must increase by one each time (TS 33.401
// §7.2.8.4.3), proving a fresh NH is derived rather than reused.
func TestEPSPathSwitchNCCIncrements(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	first := jsonGet(nasStep(t, enbID, ueID, "path_switch"), "s1ap.security_context.next_hop_chaining_count")
	if first != "2" {
		t.Fatalf("first path switch NCC = %q, want 2; body unavailable", first)
	}

	second := jsonGet(nasStep(t, enbID, ueID, "path_switch"), "s1ap.security_context.next_hop_chaining_count")
	if second != "3" {
		t.Fatalf("second path switch NCC = %q, want 3 (NCC must advance per switch, TS 33.401 §7.2.8.4.3)", second)
	}
}

// TestEPSPathSwitchUnknownUE checks the MME rejects a PATH SWITCH REQUEST naming
// a source MME-UE-S1AP-ID it never assigned, with cause unknown-mme-ue-s1ap-id
// (TS 36.413 §9.2.1.3, radio-network #13).
func TestEPSPathSwitchUnknownUE(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"path_switch","mme_ue_s1ap_id":2147483646,"timeout_ms":4000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestFailure" {
		t.Fatalf("unknown-UE path switch: s1ap.message_type = %q, want PathSwitchRequestFailure; body: %s", got, resp)
	}

	if g, v := jsonGet(resp, "s1ap.cause.group"), jsonGet(resp, "s1ap.cause.value"); g != "radio_network" || v != "13" {
		t.Fatalf("unknown-UE path switch cause = %s/%s, want radio_network/13 (unknown-mme-ue-s1ap-id); body: %s", g, v, resp)
	}
}

// TestEPSPathSwitchDuplicateERAB checks the MME rejects a PATH SWITCH REQUEST
// whose to-be-switched list repeats an E-RAB ID, with cause
// multiple-E-RAB-ID-instances (TS 36.413 §9.2.1.3, radio-network #31).
func TestEPSPathSwitchDuplicateERAB(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"path_switch","duplicate_erab":true,"timeout_ms":4000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestFailure" {
		t.Fatalf("duplicate-E-RAB path switch: s1ap.message_type = %q, want PathSwitchRequestFailure; body: %s", got, resp)
	}

	if g, v := jsonGet(resp, "s1ap.cause.group"), jsonGet(resp, "s1ap.cause.value"); g != "radio_network" || v != "31" {
		t.Fatalf("duplicate-E-RAB path switch cause = %s/%s, want radio_network/31 (multiple-E-RAB-ID-instances); body: %s", g, v, resp)
	}
}

// TestEPSPathSwitchUnknownERAB checks the MME fails a PATH SWITCH REQUEST naming
// an E-RAB the UE does not have (7; its only bearer is the default, E-RAB 5): no
// E-RAB is switched, so the MME returns a failure with cause
// transport-resource-unavailable (TS 36.413 §9.1.5.10, §9.2.1.3 transport #0).
func TestEPSPathSwitchUnknownERAB(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"path_switch","path_switch_erab_id":7,"timeout_ms":4000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestFailure" {
		t.Fatalf("unknown-E-RAB path switch: s1ap.message_type = %q, want PathSwitchRequestFailure; body: %s", got, resp)
	}

	if g, v := jsonGet(resp, "s1ap.cause.group"), jsonGet(resp, "s1ap.cause.value"); g != "transport" || v != "0" {
		t.Fatalf("unknown-E-RAB path switch cause = %s/%s, want transport/0 (transport-resource-unavailable); body: %s", g, v, resp)
	}
}
