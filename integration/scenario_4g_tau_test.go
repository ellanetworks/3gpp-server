// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func Test4GTrackingAreaUpdate(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasStep(t, enbID, ueID, "tracking_area_update")
	if got := jsonGet(resp, "nas.message_type"); got != "tracking_area_update_accept" {
		t.Fatalf("TAU: nas.message_type = %q, want tracking_area_update_accept; body: %s", got, resp)
	}
}

// The MME has no SGs interface, so a combined TA/LA update is accepted for EPS only (TS 24.301 §5.5.3.2.4).
func Test4GTAUCombined(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"tracking_area_update","eps_update_type":1}`)

	if got := jsonGet(resp, "nas.message_type"); got != "tracking_area_update_accept" {
		t.Fatalf("combined TAU: nas.message_type = %q, want tracking_area_update_accept; body: %s", got, resp)
	}

	if got := jsonGet(resp, "nas.emm_cause"); got != "18" {
		t.Fatalf("combined TAU Accept emm_cause = %q, want 18 (CS domain not available); body: %s", got, resp)
	}
}

func Test4GTAUBadMAC(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"tracking_area_update","corrupt_mac":true,"timeout_ms":3000}`)

	if got := jsonGet(resp, "nas.message_type"); got == "tracking_area_update_accept" {
		t.Fatalf("MME accepted a TAU with an invalid NAS-MAC (TS 24.301 §4.4.4); body: %s", resp)
	}
}

func Test4GTAUReplay(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	if got := jsonGet(nasStep(t, enbID, ueID, "tracking_area_update"), "nas.message_type"); got != "tracking_area_update_accept" {
		t.Fatalf("first TAU not accepted: got %q", got)
	}

	resp := nasBody(t, enbID, ueID, `{"message_type":"tracking_area_update","nas_count":0,"timeout_ms":3000}`)

	if got := jsonGet(resp, "nas.message_type"); got == "tracking_area_update_accept" {
		t.Fatalf("MME accepted a TAU with a stale NAS COUNT (TS 24.301 §4.4.3.5); body: %s", resp)
	}
}
