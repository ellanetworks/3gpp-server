// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func Test4GS1ResetAll(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"reset","reset_all":true,"timeout_ms":4000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "ResetAcknowledge" {
		t.Fatalf("S1 reset (all): s1ap.message_type = %q, want ResetAcknowledge (TS 36.413 §8.7.1.2.1); body: %s", got, resp)
	}

	after := nasBody(t, enbID, ueID, `{"message_type":"release_request","timeout_ms":3000}`)
	if got := jsonGet(after, "s1ap.message_type"); got == "UEContextReleaseCommand" {
		t.Fatalf("UE S1 connection survived a reset-all; body: %s", after)
	}

	assertEPSErrorIndication(t, after)

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

func Test4GS1ResetPartial(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	mme, enb := enbUES1APIDs(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"reset","timeout_ms":4000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "ResetAcknowledge" {
		t.Fatalf("S1 reset (partial): s1ap.message_type = %q, want ResetAcknowledge (TS 36.413 §8.7.1.2.1); body: %s", got, resp)
	}

	if got := jsonGet(resp, "s1ap.reset_connections.0.mme_ue_s1ap_id"); got != mme {
		t.Fatalf("partial reset ack MME-UE-S1AP-ID = %q, want the reset connection %q (TS 36.413 §8.7.1.2.1); body: %s", got, mme, resp)
	}

	if got := jsonGet(resp, "s1ap.reset_connections.0.enb_ue_s1ap_id"); got != enb {
		t.Fatalf("partial reset ack eNB-UE-S1AP-ID = %q, want the reset connection %q; body: %s", got, enb, resp)
	}

	after := nasBody(t, enbID, ueID, `{"message_type":"release_request","timeout_ms":3000}`)
	assertEPSErrorIndication(t, after)
}
