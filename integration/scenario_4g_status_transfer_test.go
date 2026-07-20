// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Distinct multi-octet value, so a relay that swaps or truncates the container is caught.
const statusTransferContainer = "deadbeef0102030405"

// Requires an already-prepared handover: TS 36.413 §8.4.7.3 lets a target ignore
// the message when none exists.
func assertENBStatusTransferRelayed(t *testing.T, sourceENB, targetENB, ueID string) {
	t.Helper()

	status, resp := doRequest(t, "POST", "/enb/"+sourceENB+"/ue/"+ueID+"/s1ap",
		fmt.Sprintf(`{"message_type":"enb_status_transfer","status_transfer_container":%q}`, statusTransferContainer))
	if status != 200 {
		t.Fatalf("enb_status_transfer: HTTP %d\n  body: %s", status, resp)
	}

	mmeStatus := awaitENBS1AP(t, targetENB, `["MMEStatusTransfer"]`)
	if got := jsonGet(mmeStatus, "s1ap.message_type"); got != "MMEStatusTransfer" {
		t.Fatalf("s1ap.message_type = %q, want MMEStatusTransfer — the MME must relay the source's eNB status to the target (TS 36.413 §8.4.7)\n  body: %s", got, mmeStatus)
	}

	if got := jsonGet(mmeStatus, "s1ap.enb_ue_s1ap_id"); got != fmt.Sprintf("%d", targetENBUES1APID) {
		t.Errorf("MMEStatusTransfer eNB UE S1AP ID = %q, want the target's %d (TS 36.413 §9.2.3.3)\n  body: %s",
			got, targetENBUES1APID, mmeStatus)
	}

	if got := jsonGet(mmeStatus, "s1ap.status_transfer_container"); got != statusTransferContainer {
		t.Errorf("relayed status_transfer_container = %q, want %q — the MME must convey the source's eNB Status Transfer Transparent Container to the target unchanged (TS 36.413 §8.4.7, §9.2.1.44)\n  body: %s",
			got, statusTransferContainer, mmeStatus)
	}
}

func Test4GS1HandoverStatusTransfer(t *testing.T) {
	sourceENB := createENBWithID(t, 1, "source-enb")
	targetENB := createENBWithID(t, 2, "target-enb")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	status, ueBody := doRequest(t, "GET", "/enb/"+sourceENB+"/ue/"+ueID, "")
	if status != 200 {
		t.Fatalf("get ue: HTTP %d\n  body: %s", status, ueBody)
	}

	defaultEBI := jsonGet(ueBody, "default_ebi")
	if defaultEBI == "" {
		t.Fatalf("UE has no default bearer established\n  body: %s", ueBody)
	}

	nasBody(t, sourceENB, ueID, fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, targetENB))

	hoReq := awaitENBS1AP(t, targetENB, `["HandoverRequest"]`)
	if got := jsonGet(hoReq, "s1ap.message_type"); got != "HandoverRequest" {
		t.Fatalf("s1ap.message_type = %q, want HandoverRequest (TS 36.413 §8.4.2)\n  body: %s", got, hoReq)
	}

	targetMME := jsonGet(hoReq, "s1ap.mme_ue_s1ap_id")
	if targetMME == "" {
		t.Fatalf("HandoverRequest missing MME UE S1AP ID\n  body: %s", hoReq)
	}

	status, body := doRequest(t, "POST", "/enb/"+targetENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%d,"admitted_erabs":[{"id":%s,"dl_teid":9000,"dl_ip":"10.3.0.3"}]}`,
			targetMME, targetENBUES1APID, defaultEBI))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	status, hoCmd := awaitENBUES1AP(t, sourceENB, ueID, `["HandoverCommand"]`)
	if status != 200 {
		t.Fatalf("await HandoverCommand: HTTP %d\n  body: %s", status, hoCmd)
	}

	if got := jsonGet(hoCmd, "s1ap.message_type"); got != "HandoverCommand" {
		t.Fatalf("s1ap.message_type = %q, want HandoverCommand (TS 36.413 §8.4.1)\n  body: %s", got, hoCmd)
	}

	assertENBStatusTransferRelayed(t, sourceENB, targetENB, ueID)
}
