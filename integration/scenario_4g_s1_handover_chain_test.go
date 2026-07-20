// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// s1HandoverHop drives one S1 handover of ueID from srcENB to tgtENB and migrates
// the UE onto the target, returning the target-side MME UE S1AP ID (TS 36.413 §8.4).
func s1HandoverHop(t *testing.T, srcENB, ueID, tgtENB string) string {
	t.Helper()

	const tgtENBUE = 100

	defaultEBI := jsonGet(getENBUE(t, srcENB, ueID), "default_ebi")
	if defaultEBI == "" {
		t.Fatalf("UE has no default bearer before handover %s->%s", srcENB, tgtENB)
	}

	nasBody(t, srcENB, ueID, fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, tgtENB))

	hoReq := awaitENBS1AP(t, tgtENB, `["HandoverRequest"]`)
	targetMME := jsonGet(hoReq, "s1ap.mme_ue_s1ap_id")
	if targetMME == "" {
		t.Fatalf("HandoverRequest %s->%s missing MME UE S1AP ID\n  body: %s", srcENB, tgtENB, hoReq)
	}

	status, body := doRequest(t, "POST", "/enb/"+tgtENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%d,"admitted_erabs":[{"id":%s,"dl_teid":9001,"dl_ip":"10.3.0.3"}]}`,
			targetMME, tgtENBUE, defaultEBI))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	status, hoCmd := awaitENBUES1AP(t, srcENB, ueID, `["HandoverCommand"]`)
	if status != 200 {
		t.Fatalf("await HandoverCommand %s->%s: HTTP %d\n  body: %s", srcENB, tgtENB, status, hoCmd)
	}

	if got := jsonGet(hoCmd, "s1ap.message_type"); got != "HandoverCommand" {
		t.Fatalf("hop %s->%s: s1ap.message_type = %q, want HandoverCommand (TS 36.413 §8.4.1)\n  body: %s", srcENB, tgtENB, got, hoCmd)
	}

	status, body = doRequest(t, "POST", "/enb/"+tgtENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_notify","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%d}`, targetMME, tgtENBUE))
	if status != 200 {
		t.Fatalf("handover_notify: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/enb/"+srcENB+"/ue/"+ueID+"/migrate",
		fmt.Sprintf(`{"target_enb_id":%q,"enb_ue_s1ap_id":%d}`, tgtENB, tgtENBUE))
	if status != 200 {
		t.Fatalf("migrate UE %s->%s: HTTP %d\n  body: %s", srcENB, tgtENB, status, body)
	}

	return targetMME
}

func assertMobilityTAUAccepted(t *testing.T, enbID, ueID string) {
	t.Helper()

	resp := nasStep(t, enbID, ueID, "tracking_area_update")
	if got := jsonGet(resp, "nas.message_type"); got != "tracking_area_update_accept" {
		t.Errorf("post-handover TAU: nas.message_type = %q, want tracking_area_update_accept (TS 24.301 §5.5.3)\n  body: %s", got, resp)
	}
}

func Test4GS1HandoverPingPong(t *testing.T) {
	enbA := createENBWithID(t, 1, "s1-ho-pp-a")
	enbB := createENBWithID(t, 2, "s1-ho-pp-b")

	ueID := mustCreateENBUE(t, enbA)
	fullAttach(t, enbA, ueID)

	s1HandoverHop(t, enbA, ueID, enbB)
	s1HandoverHop(t, enbB, ueID, enbA)

	assertMobilityTAUAccepted(t, enbA, ueID)
}

func Test4GS1HandoverMultiHop(t *testing.T) {
	enbA := createENBWithID(t, 1, "s1-ho-mh-a")
	enbB := createENBWithID(t, 2, "s1-ho-mh-b")
	enbC := createENBWithID(t, 3, "s1-ho-mh-c")

	ueID := mustCreateENBUE(t, enbA)
	fullAttach(t, enbA, ueID)

	s1HandoverHop(t, enbA, ueID, enbB)
	s1HandoverHop(t, enbB, ueID, enbC)

	assertMobilityTAUAccepted(t, enbC, ueID)
}

func Test4GS1HandoverConcurrentUEs(t *testing.T) {
	const tgtENBUEBase = 100

	srcENB := createENBWithID(t, 1, "s1-ho-cc-src")
	tgtENB := createENBWithID(t, 2, "s1-ho-cc-tgt")

	// Dedicated subscribers: a mid-flow abort must not dirty the shared ones.
	ue1 := createENBUEWithIMSI(t, srcENB, "001010000000005")
	ue2 := createENBUEWithIMSI(t, srcENB, "001010000000006")
	fullAttach(t, srcENB, ue1)
	fullAttach(t, srcENB, ue2)

	defaultEBI := jsonGet(getENBUE(t, srcENB, ue1), "default_ebi")

	for _, ue := range []string{ue1, ue2} {
		nasBody(t, srcENB, ue, fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q}`, tgtENB))
	}

	mme1 := jsonGet(awaitENBS1AP(t, tgtENB, `["HandoverRequest"]`), "s1ap.mme_ue_s1ap_id")
	mme2 := jsonGet(awaitENBS1AP(t, tgtENB, `["HandoverRequest"]`), "s1ap.mme_ue_s1ap_id")
	if mme1 == "" || mme2 == "" {
		t.Fatal("HandoverRequest missing MME UE S1AP ID")
	}

	if mme1 == mme2 {
		t.Fatalf("concurrent handovers shared MME UE S1AP ID %s — UE contexts not isolated", mme1)
	}

	for i, mme := range []string{mme1, mme2} {
		status, body := doRequest(t, "POST", "/enb/"+tgtENB+"/s1ap",
			fmt.Sprintf(`{"message_type":"handover_request_acknowledge","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%d,"admitted_erabs":[{"id":%s,"dl_teid":9001,"dl_ip":"10.3.0.3"}]}`,
				mme, tgtENBUEBase+i, defaultEBI))
		if status != 200 {
			t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
		}
	}

	for _, ue := range []string{ue1, ue2} {
		status, cmd := awaitENBUES1AP(t, srcENB, ue, `["HandoverCommand"]`)
		if status != 200 || jsonGet(cmd, "s1ap.message_type") != "HandoverCommand" {
			t.Fatalf("await HandoverCommand for ue %s: HTTP %d\n  body: %s", ue, status, cmd)
		}
	}
}
