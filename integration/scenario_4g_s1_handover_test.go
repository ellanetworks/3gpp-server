// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"strings"
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

// BuildHandoverRequired emits this one-octet stub, which the EPC passes to the target unread (TS 36.413 §9.2.1.56).
const sourceToTargetContainer = "00"

// The MME stores 0xC000 for the UE's advertised EEA0/1/2 + EIA0/1/2, the S1AP bitmap carrying no EEA0/EIA0 bit.
const storedUESecurityCapabilities = "c000"

// NCC seeds at 1 at Initial Context Setup and the source MME advances it by one on HANDOVER REQUIRED, so the first S1 handover after attach carries 2 (TS 33.401 §7.2.8.1.1, §7.2.8.4.3).
func assertHandoverRequestSecurity(t *testing.T, hoReq []byte) {
	t.Helper()

	if got := jsonGet(hoReq, "s1ap.security_context.next_hop_chaining_count"); got != "2" {
		t.Errorf("HandoverRequest NCC = %q, want 2 (TS 33.401 §7.2.8.4.3)\n  body: %s", got, hoReq)
	}

	nh := jsonGet(hoReq, "s1ap.security_context.next_hop")
	if len(nh) != 64 {
		t.Errorf("HandoverRequest NH = %q, want a 256-bit (64-hex) Next Hop (TS 36.413 §9.2.1.26)\n  body: %s", nh, hoReq)
	}

	if nh == strings.Repeat("0", 64) {
		t.Errorf("HandoverRequest NH is all-zero, not a fresh derived key (TS 33.401 §7.2.8.4.3)\n  body: %s", hoReq)
	}
}

// The UE Security Capabilities and the Source to Target Transparent Container reach the target unmodified (TS 36.413 §9.2.1.40, §9.2.1.56; TS 33.401 §7.2.4.2.3).
func assertHandoverRequestMandatoryIEs(t *testing.T, hoReq []byte) {
	t.Helper()

	if got := jsonGet(hoReq, "s1ap.ue_security_capabilities.encryption_algorithms"); got != storedUESecurityCapabilities {
		t.Errorf("HandoverRequest encryption algorithms = %q, want %s (TS 36.413 §9.2.1.40)\n  body: %s", got, storedUESecurityCapabilities, hoReq)
	}

	if got := jsonGet(hoReq, "s1ap.ue_security_capabilities.integrity_protection_algorithms"); got != storedUESecurityCapabilities {
		t.Errorf("HandoverRequest integrity algorithms = %q, want %s (TS 36.413 §9.2.1.40)\n  body: %s", got, storedUESecurityCapabilities, hoReq)
	}

	if got := jsonGet(hoReq, "s1ap.source_to_target_transparent_container"); got != sourceToTargetContainer {
		t.Errorf("HandoverRequest Source to Target Transparent Container = %q, want %q (TS 36.413 §9.2.1.56)\n  body: %s", got, sourceToTargetContainer, hoReq)
	}

	dl := jsonGet(hoReq, "s1ap.ue_aggregate_max_bit_rate.dl")
	ul := jsonGet(hoReq, "s1ap.ue_aggregate_max_bit_rate.ul")

	if dl == "0" && ul == "0" {
		t.Errorf("HandoverRequest UE AMBR DL and UL are both zero, a logical error (TS 36.413 §9.2.1.20)\n  body: %s", hoReq)
	}
}

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

	assertHandoverRequestSecurity(t, hoReq)
	assertHandoverRequestMandatoryIEs(t, hoReq)

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

	status, body = doRequest(t, "POST", "/enb/"+sourceENB+"/ue/"+ueID+"/s1ap",
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
