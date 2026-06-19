// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// TestEPSS1ResetAll drives an eNB-initiated full S1 RESET (s1-Interface,
// reset-all). Per TS 36.413 §8.7.1.2.1 the MME releases every UE-associated
// logical S1 connection on the association and replies with a Reset Acknowledge.
func TestEPSS1ResetAll(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"reset","reset_all":true,"timeout_ms":4000}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "ResetAcknowledge" {
		t.Fatalf("S1 reset (all): s1ap.message_type = %q, want ResetAcknowledge (TS 36.413 §8.7.1.2.1); body: %s", got, resp)
	}

	// The reset released the UE's S1 connection: a UE-associated message on its
	// now-released MME-UE-S1AP-ID draws an Error Indication (TS 36.413 §10.6).
	after := nasBody(t, enbID, ueID, `{"message_type":"release_request","timeout_ms":3000}`)
	if got := jsonGet(after, "s1ap.message_type"); got == "UEContextReleaseCommand" {
		t.Fatalf("UE S1 connection survived a reset-all; body: %s", after)
	}

	assertEPSErrorIndication(t, after)

	// The MME must remain healthy: a fresh UE still attaches.
	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// TestEPSS1ResetPartial drives an eNB-initiated partial S1 RESET
// (partOfS1-Interface) naming one UE's connection. Per TS 36.413 §8.7.1.2.1 the
// MME releases that connection and replies with a Reset Acknowledge whose
// connection list echoes the UE S1AP ID pair it acted on.
func TestEPSS1ResetPartial(t *testing.T) {
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

	// The named connection was released: a message on it draws an Error Indication.
	after := nasBody(t, enbID, ueID, `{"message_type":"release_request","timeout_ms":3000}`)
	assertEPSErrorIndication(t, after)
}
