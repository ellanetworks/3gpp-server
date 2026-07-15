// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// createENBWithID creates an eNB on a caller-chosen Global eNB ID, opening its
// own S1 association.
func createENBWithID(t *testing.T, enbID int, name string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"mme_address": "10.3.0.2:36412",
		"enb_s1_address": "10.3.0.3",
		"mcc": "001", "mnc": "01",
		"tac": "0001", "enb_id": %d,
		"name": %q
	}`, enbID, name)

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create enb %d: HTTP %d: %s", enbID, status, resp)
	}

	id := jsonGet(resp, "enb_id")
	if id == "" {
		t.Fatalf("create enb %d: no enb_id in response: %s", enbID, resp)
	}

	t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })

	return id
}

// enbUES1APIDs returns the UE's S1AP ID pair as decimal strings, ready to splice
// into a JSON number field.
func enbUES1APIDs(t *testing.T, enbID, ueID string) (mme, enb string) {
	t.Helper()

	status, body := doRequest(t, "GET", "/enb/"+enbID+"/ue/"+ueID, "")
	if status != 200 {
		t.Fatalf("get ue: HTTP %d: %s", status, body)
	}

	mme, enb = jsonGet(body, "mme_ue_s1ap_id"), jsonGet(body, "enb_ue_s1ap_id")
	if mme == "" || enb == "" {
		t.Fatalf("get ue: missing S1AP IDs: %s", body)
	}

	return mme, enb
}

// Test4GCrossENBReleaseHijack forges the victim's S1AP ID pair in a UE Context
// Release Request on the attacker's own association. The pair names a
// UE-associated connection unknown on that association, so the MME must answer
// with an Error Indication (TS 36.413 §10.6) and leave the victim served.
func Test4GCrossENBReleaseHijack(t *testing.T) {
	victimENB := createENBWithID(t, 1, "victim-enb")
	attackerENB := createENBWithID(t, 2, "attacker-enb")

	victimUE := mustCreateENBUE(t, victimENB)
	fullAttach(t, victimENB, victimUE)

	vMME, vENB := enbUES1APIDs(t, victimENB, victimUE)

	// The attacker needs only its own association up; the UE is the API vehicle.
	attackerUE := mustCreateENBUE(t, attackerENB)

	resp := nasBody(t, attackerENB, attackerUE, fmt.Sprintf(
		`{"message_type":"release_request","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%s,"timeout_ms":3000}`, vMME, vENB))

	if got := jsonGet(resp, "s1ap.message_type"); got == "UEContextReleaseCommand" {
		t.Fatalf("a rogue eNB released another eNB's UE (cross-association hijack); body: %s", resp)
	}

	assertEPSErrorIndication(t, resp)
}

// Test4GCrossENBUECapabilityHijack forges the victim's S1AP ID pair in a UE
// Capability Info Indication, which carries no integrity protection: only the
// binding of the UE-associated connection to its own association stops the MME
// storing attacker-chosen capability bytes against the victim. The MME must
// reject it with an Error Indication (TS 36.413 §10.6).
func Test4GCrossENBUECapabilityHijack(t *testing.T) {
	victimENB := createENBWithID(t, 1, "victim-enb")
	attackerENB := createENBWithID(t, 2, "attacker-enb")

	victimUE := mustCreateENBUE(t, victimENB)
	fullAttach(t, victimENB, victimUE)

	vMME, vENB := enbUES1APIDs(t, victimENB, victimUE)

	attackerUE := mustCreateENBUE(t, attackerENB)

	resp := nasBody(t, attackerENB, attackerUE, fmt.Sprintf(
		`{"message_type":"ue_capability_info","ue_radio_capability":"deadbeef","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%s,"timeout_ms":3000}`, vMME, vENB))

	assertEPSErrorIndication(t, resp)
}
