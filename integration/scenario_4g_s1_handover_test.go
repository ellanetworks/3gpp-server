// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func awaitENBS1AP(t *testing.T, enbID string, messageTypes string) []byte {
	t.Helper()

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/await",
		fmt.Sprintf(`{"message_types":%s,"timeout_ms":5000}`, messageTypes))
	if status != 200 {
		t.Fatalf("await %s on enb %s: HTTP %d\n  body: %s", messageTypes, enbID, status, body)
	}

	return body
}

func awaitENBUES1AP(t *testing.T, enbID, ueID string, messageTypes string) (int, []byte) {
	t.Helper()

	return doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		fmt.Sprintf(`{"message_types":%s,"timeout_ms":5000}`, messageTypes))
}

// The target assigns this to the incoming UE and must reuse it across the Handover Request Acknowledge and Notify (TS 36.413 §8.4.2, §8.4.3).
const targetENBUES1APID = 100

func runS1HandoverFlow(t *testing.T, sourceENB, targetENB, ueID string) {
	t.Helper()

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

	if got := jsonGet(hoReq, "s1ap.erab_setup_items.0.erab_id"); got != defaultEBI {
		t.Fatalf("HandoverRequest E-RAB ID = %q, want %q (the bearer established at attach, TS 36.413 §9.1.5.4)\n  body: %s", got, defaultEBI, hoReq)
	}

	if nh := jsonGet(hoReq, "s1ap.security_context.next_hop"); nh == "" {
		t.Errorf("HandoverRequest missing Security Context (mandatory, TS 36.413 §9.1.5.4)\n  body: %s", hoReq)
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

	const statusContainer = "0a1b2c3d"

	status, body = doRequest(t, "POST", "/enb/"+sourceENB+"/ue/"+ueID+"/nas",
		fmt.Sprintf(`{"message_type":"enb_status_transfer","status_transfer_container":%q}`, statusContainer))
	if status != 200 {
		t.Fatalf("enb_status_transfer: HTTP %d\n  body: %s", status, body)
	}

	mmeStatus := awaitENBS1AP(t, targetENB, `["MMEStatusTransfer"]`)
	if got := jsonGet(mmeStatus, "s1ap.message_type"); got != "MMEStatusTransfer" {
		t.Errorf("s1ap.message_type = %q, want MMEStatusTransfer (the MME must relay eNB status, TS 36.413 §8.4.7)\n  body: %s", got, mmeStatus)
	}

	if got := jsonGet(mmeStatus, "s1ap.status_transfer_container"); got != statusContainer {
		t.Errorf("relayed status_transfer_container = %q, want %q — the MME must convey the source's status container to the target unchanged (TS 36.413 §8.4.7, §9.2.1.44)\n  body: %s",
			got, statusContainer, mmeStatus)
	}

	status, body = doRequest(t, "POST", "/enb/"+targetENB+"/s1ap",
		fmt.Sprintf(`{"message_type":"handover_notify","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%d}`,
			targetMME, targetENBUES1APID))
	if status != 200 {
		t.Fatalf("handover_notify: HTTP %d\n  body: %s", status, body)
	}

	status, rel := awaitENBUES1AP(t, sourceENB, ueID, `["UEContextReleaseCommand"]`)
	if status != 200 {
		t.Fatalf("await UEContextReleaseCommand: HTTP %d — source must be released after handover\n  body: %s", status, rel)
	}

	if got := jsonGet(rel, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("s1ap.message_type = %q, want UEContextReleaseCommand (source released after handover)\n  body: %s", got, rel)
	}
}

func Test4GS1Handover(t *testing.T) {
	sourceENB := createENBWithID(t, 1, "source-enb")
	targetENB := createENBWithID(t, 2, "target-enb")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	runS1HandoverFlow(t, sourceENB, targetENB, ueID)
}

func Test4GS1HandoverThenMigrate(t *testing.T) {
	sourceENB := createENBWithID(t, 1, "source-enb")
	targetENB := createENBWithID(t, 2, "target-enb")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	runS1HandoverFlow(t, sourceENB, targetENB, ueID)

	status, body := doRequest(t, "POST", "/enb/"+sourceENB+"/ue/"+ueID+"/migrate",
		fmt.Sprintf(`{"target_enb_id":%q,"enb_ue_s1ap_id":%d}`, targetENB, targetENBUES1APID))
	if status != 200 {
		t.Fatalf("migrate: HTTP %d\n  body: %s", status, body)
	}

	if status, _ := doRequest(t, "GET", "/enb/"+targetENB+"/ue/"+ueID, ""); status != 200 {
		t.Errorf("UE not reachable on the target eNB after migrate (HTTP %d)", status)
	}

	if status, _ := doRequest(t, "GET", "/enb/"+sourceENB+"/ue/"+ueID, ""); status == 200 {
		t.Errorf("UE still present on the source eNB after migrate")
	}
}
