// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// S1 handover failure paths (TS 36.413 §8.4.1.3, §8.4.2.3): when the target eNB
// rejects the handover or the target eNB is unknown, the MME must abort the
// preparation and return a HANDOVER PREPARATION FAILURE to the source eNB. A
// failure of these tests means Ella Core deviates.

package integration_test

import (
	"fmt"
	"testing"
)

// createUnconnectedENB creates an eNB in the tester without opening its S1
// association, so its Global eNB-ID is known to the tester but not to the MME —
// a valid handover target identity the MME cannot resolve.
func createUnconnectedENB(t *testing.T, enbID int, name string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"mme_address": "10.3.0.2:36412",
		"enb_s1_address": "10.3.0.3",
		"mcc": "001", "mnc": "01",
		"tac": "0001", "enb_id": %d,
		"name": %q, "skip_s1_setup": true
	}`, enbID, name)

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create unconnected enb %d: HTTP %d: %s", enbID, status, resp)
	}

	id := jsonGet(resp, "enb_id")
	t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })

	return id
}

// Test4GS1HandoverTargetRejects checks that when the target eNB answers the
// resource allocation with HANDOVER FAILURE, the MME aborts preparation and
// returns HANDOVER PREPARATION FAILURE to the source (TS 36.413 §8.4.2.3).
func Test4GS1HandoverTargetRejects(t *testing.T) {
	sourceENB := createENBWithID(t, 1, "source-enb")
	targetENB := createENBWithID(t, 2, "target-enb")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	status, body := doRequest(t, "POST", "/enb/"+sourceENB+"/ue/"+ueID+"/nas",
		fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, targetENB))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitENBS1AP(t, targetENB, `["HandoverRequest"]`)
	targetMME := jsonGet(hoReq, "s1ap.mme_ue_s1ap_id")
	if targetMME == "" {
		t.Fatalf("HandoverRequest missing MME UE S1AP ID\n  body: %s", hoReq)
	}

	// Target eNB → MME: HANDOVER FAILURE.
	status, body = doRequest(t, "POST", "/enb/"+targetENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_failure","mme_ue_s1ap_id":%s}`, targetMME))
	if status != 200 {
		t.Fatalf("handover_failure: HTTP %d\n  body: %s", status, body)
	}

	// MME → source eNB: HANDOVER PREPARATION FAILURE.
	status, fail := awaitENBUES1AP(t, sourceENB, ueID, `["HandoverPreparationFailure"]`)
	if status != 200 {
		t.Fatalf("await HandoverPreparationFailure: HTTP %d — the MME must fail the preparation to the source\n  body: %s", status, fail)
	}

	if got := jsonGet(fail, "s1ap.message_type"); got != "HandoverPreparationFailure" {
		t.Errorf("s1ap.message_type = %q, want HandoverPreparationFailure (TS 36.413 §8.4.2.3)\n  body: %s", got, fail)
	}

	if g := jsonGet(fail, "s1ap.cause.group"); g == "" {
		t.Errorf("HandoverPreparationFailure missing mandatory Cause IE (TS 36.413 §9.1.5.3)\n  body: %s", fail)
	}
}

// Test4GS1HandoverUnknownTarget checks that a HANDOVER REQUIRED naming a target
// eNB the MME does not serve is rejected with HANDOVER PREPARATION FAILURE
// (cause unknown-targetID, TS 36.413 §8.4.1.3).
func Test4GS1HandoverUnknownTarget(t *testing.T) {
	sourceENB := createENBWithID(t, 1, "source-enb")
	unknownTarget := createUnconnectedENB(t, 99, "unconnected-enb")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	status, body := doRequest(t, "POST", "/enb/"+sourceENB+"/ue/"+ueID+"/nas",
		fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, unknownTarget))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	status, fail := awaitENBUES1AP(t, sourceENB, ueID, `["HandoverPreparationFailure"]`)
	if status != 200 {
		t.Fatalf("await HandoverPreparationFailure: HTTP %d — an unknown target must fail preparation\n  body: %s", status, fail)
	}

	if got := jsonGet(fail, "s1ap.message_type"); got != "HandoverPreparationFailure" {
		t.Errorf("s1ap.message_type = %q, want HandoverPreparationFailure for an unknown target (TS 36.413 §8.4.1.3)\n  body: %s", got, fail)
	}
}
