// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func handoverRequestERABIDs(hoReq []byte) []string {
	var ids []string

	for i := 0; ; i++ {
		id := jsonGet(hoReq, fmt.Sprintf("s1ap.erab_setup_items.%d.erab_id", i))
		if id == "" {
			break
		}

		ids = append(ids, id)
	}

	return ids
}

func hasString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}

	return false
}

func Test4GS1HandoverMultipleBearers(t *testing.T) {
	const tgtENBUE = 100

	srcENB := createENBWithID(t, 1, "s1-ho-mb-src")
	tgtENB := createENBWithID(t, 2, "s1-ho-mb-tgt")

	ueID := mustCreateENBUE(t, srcENB)
	secondEBI := connectSecondPDN(t, srcENB, ueID)
	defaultEBI := jsonGet(getENBUE(t, srcENB, ueID), "default_ebi")

	nasBody(t, srcENB, ueID, fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, tgtENB))

	hoReq := awaitENBS1AP(t, tgtENB, `["HandoverRequest"]`)
	targetMME := jsonGet(hoReq, "s1ap.mme_ue_s1ap_id")
	if targetMME == "" {
		t.Fatalf("HandoverRequest missing MME UE S1AP ID\n  body: %s", hoReq)
	}

	erabs := handoverRequestERABIDs(hoReq)
	if !hasString(erabs, defaultEBI) || !hasString(erabs, secondEBI) {
		t.Fatalf("HandoverRequest E-RAB list = %v, want both %s and %s (TS 36.413 §9.1.5.4)\n  body: %s", erabs, defaultEBI, secondEBI, hoReq)
	}

	status, body := doRequest(t, "POST", "/enb/"+tgtENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%d,"admitted_erabs":[{"id":%s,"dl_teid":9001,"dl_ip":"10.3.0.3"},{"id":%s,"dl_teid":9002,"dl_ip":"10.3.0.3"}]}`,
			targetMME, tgtENBUE, defaultEBI, secondEBI))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	status, hoCmd := awaitENBUES1AP(t, srcENB, ueID, `["HandoverCommand"]`)
	if status != 200 || jsonGet(hoCmd, "s1ap.message_type") != "HandoverCommand" {
		t.Fatalf("await HandoverCommand: HTTP %d\n  body: %s", status, hoCmd)
	}
}

func Test4GS1HandoverPartialAdmission(t *testing.T) {
	const tgtENBUE = 100

	srcENB := createENBWithID(t, 1, "s1-ho-part-src")
	tgtENB := createENBWithID(t, 2, "s1-ho-part-tgt")

	ueID := mustCreateENBUE(t, srcENB)
	secondEBI := connectSecondPDN(t, srcENB, ueID)
	defaultEBI := jsonGet(getENBUE(t, srcENB, ueID), "default_ebi")

	nasBody(t, srcENB, ueID, fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, tgtENB))

	hoReq := awaitENBS1AP(t, tgtENB, `["HandoverRequest"]`)
	targetMME := jsonGet(hoReq, "s1ap.mme_ue_s1ap_id")
	if targetMME == "" {
		t.Fatalf("HandoverRequest missing MME UE S1AP ID\n  body: %s", hoReq)
	}

	erabs := handoverRequestERABIDs(hoReq)
	if !hasString(erabs, defaultEBI) || !hasString(erabs, secondEBI) {
		t.Fatalf("HandoverRequest E-RAB list = %v, want both %s and %s (TS 36.413 §9.1.5.4)\n  body: %s", erabs, defaultEBI, secondEBI, hoReq)
	}

	status, body := doRequest(t, "POST", "/enb/"+tgtENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%d,"admitted_erabs":[{"id":%s,"dl_teid":9001,"dl_ip":"10.3.0.3"}],"failed_erabs":[%s]}`,
			targetMME, tgtENBUE, defaultEBI, secondEBI))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	status, hoCmd := awaitENBUES1AP(t, srcENB, ueID, `["HandoverCommand"]`)
	if status != 200 || jsonGet(hoCmd, "s1ap.message_type") != "HandoverCommand" {
		t.Fatalf("await HandoverCommand: HTTP %d\n  body: %s", status, hoCmd)
	}

	if got := jsonGet(hoCmd, "s1ap.released_erabs.0"); got != secondEBI {
		t.Errorf("HandoverCommand released E-RAB = %q, want %s — the target-failed bearer must be released to the source (TS 36.413 §8.4.1.2)\n  body: %s", got, secondEBI, hoCmd)
	}
}
