// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// Test4GInitialContextSetup_UEAMBR checks the MME's Initial Context Setup Request
// carries the UE-AMBR (TS 36.413 §9.2.1.20). The Attach Accept rides in the ICS
// Request, so the security_mode_complete reply exposes it.
func Test4GInitialContextSetup_UEAMBR(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	nasStep(t, enbID, ueID, "attach_request")
	nasStep(t, enbID, ueID, "authentication_response")
	ics := nasStep(t, enbID, ueID, "security_mode_complete")

	if got := jsonGet(ics, "nas.message_type"); got != "attach_accept" {
		t.Fatalf("security_mode_complete: nas.message_type = %q, want attach_accept\n  body: %s", got, ics)
	}

	if dl := jsonGet(ics, "s1ap.ue_aggregate_max_bit_rate.dl"); dl == "" || dl == "0" {
		t.Fatalf("ICS Request UE-AMBR dl = %q, want a non-zero provisioned value (TS 36.413 §9.2.1.20)\n  body: %s", dl, ics)
	}

	if ul := jsonGet(ics, "s1ap.ue_aggregate_max_bit_rate.ul"); ul == "" || ul == "0" {
		t.Fatalf("ICS Request UE-AMBR ul = %q, want a non-zero provisioned value (TS 36.413 §9.2.1.20)\n  body: %s", ul, ics)
	}

	nasStep(t, enbID, ueID, "attach_complete")
}
