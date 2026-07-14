// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// S1 handover cancellation (TS 36.413 §8.4.5): the source eNB aborts a handover
// it has prepared, and the MME releases the reserved target resources and
// answers with HANDOVER CANCEL ACKNOWLEDGE. A failure means Ella Core deviates.

package integration_test

import (
	"fmt"
	"testing"
)

// Test4GS1HandoverCancel checks that after a handover is prepared, a HANDOVER
// CANCEL from the source is acknowledged and the UE remains served by the source
// (TS 36.413 §8.4.5).
func Test4GS1HandoverCancel(t *testing.T) {
	sourceENB := createENBWithID(t, 1, "source-enb")
	targetENB := createENBWithID(t, 2, "target-enb")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	status, body := doRequest(t, "POST", "/enb/"+sourceENB+"/ue/"+ueID+"/nas",
		fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, targetENB))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	// Wait for the preparation to reach the target before cancelling, so the MME
	// has a prepared handover to cancel.
	awaitENBS1AP(t, targetENB, `["HandoverRequest"]`)

	// Source eNB → MME: HANDOVER CANCEL. The handler returns the acknowledge.
	ack := nasBody(t, sourceENB, ueID, `{"message_type":"handover_cancel","timeout_ms":5000}`)
	if got := jsonGet(ack, "s1ap.message_type"); got != "HandoverCancelAcknowledge" {
		t.Fatalf("s1ap.message_type = %q, want HandoverCancelAcknowledge (TS 36.413 §8.4.5)\n  body: %s", got, ack)
	}

	// The UE is still served by the source: a normal release now succeeds.
	if got := jsonGet(nasStep(t, sourceENB, ueID, "release_request"), "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("after cancel the source must still serve the UE; release_request did not yield a UEContextReleaseCommand")
	}
}
