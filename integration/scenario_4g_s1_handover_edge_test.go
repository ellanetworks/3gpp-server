// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Above the MME's sequential allocation (MME-UE-S1AP-ID is 32-bit, TS 36.413 §9.2.3.3).
const unknownMMEUES1APID = 4294967295

// The maximum eNB-UE-S1AP-ID (24-bit, INTEGER (0..16777215), TS 36.413), above any live allocation.
const unknownENBUES1APID = 16777215

func expectENBErrorIndication(t *testing.T, enbID, context string) {
	t.Helper()

	ind := awaitENBS1AP(t, enbID, `["ErrorIndication"]`)
	if got := jsonGet(ind, "s1ap.message_type"); got != "ErrorIndication" {
		t.Errorf("%s: s1ap.message_type = %q, want ErrorIndication (TS 36.413 §10.6)\n  body: %s", context, got, ind)
	}
}

func expectENBHandoverPreparationFailure(t *testing.T, enbID, context string) {
	t.Helper()

	fail := awaitENBS1AP(t, enbID, `["HandoverPreparationFailure"]`)
	if got := jsonGet(fail, "s1ap.message_type"); got != "HandoverPreparationFailure" {
		t.Errorf("%s: s1ap.message_type = %q, want HandoverPreparationFailure (TS 36.413 §8.4.3)\n  body: %s", context, got, fail)
	}
}

func Test4GS1HandoverRequiredUnknownMmeUeS1apID(t *testing.T) {
	srcENB := createENBWithID(t, 1, "s1-edge-uk-mme-src")
	tgtENB := createENBWithID(t, 2, "s1-edge-uk-mme-tgt")

	ueID := mustCreateENBUE(t, srcENB)
	fullAttach(t, srcENB, ueID)

	status, body := doRequest(t, "POST", "/enb/"+srcENB+"/ue/"+ueID+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q,"mme_ue_s1ap_id_override":%d}`, tgtENB, unknownMMEUES1APID))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectENBErrorIndication(t, srcENB, "HandoverRequired with unknown MME UE S1AP ID")
}

func Test4GS1HandoverRequiredInconsistentEnbUeS1apID(t *testing.T) {
	srcENB := createENBWithID(t, 1, "s1-edge-ic-enb-src")
	tgtENB := createENBWithID(t, 2, "s1-edge-ic-enb-tgt")

	ueID := mustCreateENBUE(t, srcENB)
	fullAttach(t, srcENB, ueID)

	status, body := doRequest(t, "POST", "/enb/"+srcENB+"/ue/"+ueID+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q,"enb_ue_s1ap_id_override":%d}`, tgtENB, unknownENBUES1APID))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectENBErrorIndication(t, srcENB, "HandoverRequired with inconsistent eNB UE S1AP ID")
}

func Test4GS1HandoverRequiredUnregisteredUE(t *testing.T) {
	srcENB := createENBWithID(t, 1, "s1-edge-unreg-src")
	tgtENB := createENBWithID(t, 2, "s1-edge-unreg-tgt")

	ueID := mustCreateENBUE(t, srcENB)

	status, body := doRequest(t, "POST", "/enb/"+srcENB+"/ue/"+ueID+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, tgtENB))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectENBErrorIndication(t, srcENB, "HandoverRequired for an unregistered UE")
}

func Test4GS1HandoverRequiredUnknownTarget(t *testing.T) {
	srcENB := createENBWithID(t, 1, "s1-edge-uk-tgt-src")
	// In the store so the source can name it, but with no S1 association the MME knows nothing of.
	tgtENB := createUnconnectedENB(t, 2, "s1-edge-uk-tgt")

	ueID := mustCreateENBUE(t, srcENB)
	fullAttach(t, srcENB, ueID)

	status, body := doRequest(t, "POST", "/enb/"+srcENB+"/ue/"+ueID+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, tgtENB))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectENBHandoverPreparationFailure(t, srcENB, "HandoverRequired to a target eNB the MME has no S1 association with")
}

func Test4GS1HandoverRequestAcknowledgeUnknownMmeUeS1apID(t *testing.T) {
	srcENB := createENBWithID(t, 1, "s1-edge-ack-src")
	tgtENB := createENBWithID(t, 2, "s1-edge-ack-tgt")

	ueID := mustCreateENBUE(t, srcENB)
	fullAttach(t, srcENB, ueID)

	defaultEBI := jsonGet(getENBUE(t, srcENB, ueID), "default_ebi")

	nasBody(t, srcENB, ueID, fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, tgtENB))

	if got := jsonGet(awaitENBS1AP(t, tgtENB, `["HandoverRequest"]`), "s1ap.message_type"); got != "HandoverRequest" {
		t.Fatalf("expected HandoverRequest on target, got %q", got)
	}

	status, body := doRequest(t, "POST", "/enb/"+tgtENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","mme_ue_s1ap_id":%d,"enb_ue_s1ap_id":%d,"admitted_erabs":[{"id":%s,"dl_teid":9000,"dl_ip":"10.3.0.3"}]}`,
			unknownMMEUES1APID, targetENBUES1APID, defaultEBI))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	expectENBErrorIndication(t, tgtENB, "HandoverRequestAcknowledge with unknown MME UE S1AP ID")
}

func Test4GS1HandoverNotifyUnknownMmeUeS1apID(t *testing.T) {
	srcENB := createENBWithID(t, 1, "s1-edge-notify-src")
	tgtENB := createENBWithID(t, 2, "s1-edge-notify-tgt")

	ueID := mustCreateENBUE(t, srcENB)
	fullAttach(t, srcENB, ueID)

	defaultEBI := jsonGet(getENBUE(t, srcENB, ueID), "default_ebi")

	nasBody(t, srcENB, ueID, fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, tgtENB))

	hoReq := awaitENBS1AP(t, tgtENB, `["HandoverRequest"]`)
	targetMME := jsonGet(hoReq, "s1ap.mme_ue_s1ap_id")
	if targetMME == "" {
		t.Fatalf("HandoverRequest missing MME UE S1AP ID\n  body: %s", hoReq)
	}

	status, body := doRequest(t, "POST", "/enb/"+tgtENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%d,"admitted_erabs":[{"id":%s,"dl_teid":9000,"dl_ip":"10.3.0.3"}]}`,
			targetMME, targetENBUES1APID, defaultEBI))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	if status, cmd := awaitENBUES1AP(t, srcENB, ueID, `["HandoverCommand"]`); status != 200 || jsonGet(cmd, "s1ap.message_type") != "HandoverCommand" {
		t.Fatalf("await HandoverCommand: HTTP %d\n  body: %s", status, cmd)
	}

	status, body = doRequest(t, "POST", "/enb/"+tgtENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_notify","mme_ue_s1ap_id":%d,"enb_ue_s1ap_id":%d}`, unknownMMEUES1APID, targetENBUES1APID))
	if status != 200 {
		t.Fatalf("handover_notify: HTTP %d\n  body: %s", status, body)
	}

	expectENBErrorIndication(t, tgtENB, "HandoverNotify with unknown MME UE S1AP ID")
}
