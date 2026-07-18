// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test4GS1HandoverCancel(t *testing.T) {
	sourceENB := createENBWithID(t, 1, "source-enb")
	targetENB := createENBWithID(t, 2, "target-enb")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	status, body := doRequest(t, "POST", "/enb/"+sourceENB+"/ue/"+ueID+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, targetENB))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	// The cancel must reach the MME with a prepared handover to cancel.
	awaitENBS1AP(t, targetENB, `["HandoverRequest"]`)

	ack := nasBody(t, sourceENB, ueID, `{"message_type":"handover_cancel","timeout_ms":5000}`)
	if got := jsonGet(ack, "s1ap.message_type"); got != "HandoverCancelAcknowledge" {
		t.Fatalf("s1ap.message_type = %q, want HandoverCancelAcknowledge (TS 36.413 §8.4.5)\n  body: %s", got, ack)
	}

	// The HandoverRequest reserved a UE context on the target, which the cancel must release (TS 36.413 §8.4.5.2).
	status, rel := doRequest(t, "POST", "/enb/"+targetENB+"/await",
		`{"message_types":["UEContextReleaseCommand"],"timeout_ms":5000}`)
	if status != 200 {
		t.Errorf("await UEContextReleaseCommand on the target: HTTP %d — the EPC must release the resources it reserved for the cancelled handover preparation (TS 36.413 §8.4.5.2)\n  body: %s", status, rel)
	}

	if got := jsonGet(nasStep(t, sourceENB, ueID, "release_request"), "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("after cancel the source must still serve the UE; release_request did not yield a UEContextReleaseCommand")
	}
}
