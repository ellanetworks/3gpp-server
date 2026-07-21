// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func sendENBPathSwitch(t *testing.T, targetENB, mmeID string, freshENBID int64) (int, []byte) {
	t.Helper()

	body := fmt.Sprintf(
		`{"message_type":"path_switch_request","mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%d,"erabs":[{"id":5}],"wait_for":["PathSwitchRequestAcknowledge","PathSwitchRequestFailure","ErrorIndication"],"timeout_ms":5000}`,
		mmeID, freshENBID)

	return doRequest(t, "POST", "/enb/"+targetENB+"/s1ap", body)
}

// The source's MME-UE-S1AP-ID is unchanged by the switch; its eNB-UE-S1AP-ID goes stale.
func moveENBPathToTarget(t *testing.T, sourceENB, targetENB, ueID string, freshENBID int64) string {
	t.Helper()

	mmeID, _ := enbUES1APIDs(t, sourceENB, ueID)

	status, body := sendENBPathSwitch(t, targetENB, mmeID, freshENBID)
	if status != 200 {
		t.Fatalf("initial path switch to target: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "s1ap.message_type"); got != "PathSwitchRequestAcknowledge" {
		t.Fatalf("initial path switch to target: s1ap.message_type = %q, want PathSwitchRequestAcknowledge\n  body: %s", got, body)
	}

	return mmeID
}

func assertENBUEStillSwitchable(t *testing.T, targetENB, mmeID string, freshENBID int64, context string) {
	t.Helper()

	status, body := sendENBPathSwitch(t, targetENB, mmeID, freshENBID)
	if status != 200 || jsonGet(body, "s1ap.message_type") != "PathSwitchRequestAcknowledge" {
		t.Errorf("%s: s1ap.message_type = %q, want PathSwitchRequestAcknowledge\n  body: %s", context, jsonGet(body, "s1ap.message_type"), body)
	}
}

func Test4GPathSwitchStaleSourceReleaseRejected(t *testing.T) {
	sourceENB := createENBWithID(t, claimENBID(), "ps-stale-rel-src")
	targetENB := createENBWithID(t, claimENBID(), "ps-stale-rel-tgt")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	mmeID := moveENBPathToTarget(t, sourceENB, targetENB, ueID, 700001)

	resp := nasBody(t, sourceENB, ueID, `{"message_type":"ue_context_release_request","timeout_ms":4000}`)
	if got := jsonGet(resp, "s1ap.message_type"); got != "ErrorIndication" {
		t.Errorf("stale source UE Context Release Request: s1ap.message_type = %q, want ErrorIndication (TS 36.413 §10.6)\n  body: %s", got, resp)
	}

	assertENBUEStillSwitchable(t, targetENB, mmeID, 700002, "UE survives a stale source UE Context Release Request")
}

func Test4GPathSwitchStaleSourceUplinkNASRejected(t *testing.T) {
	sourceENB := createENBWithID(t, claimENBID(), "ps-stale-nas-src")
	targetENB := createENBWithID(t, claimENBID(), "ps-stale-nas-tgt")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	moveENBPathToTarget(t, sourceENB, targetENB, ueID, 700003)

	resp := nasBody(t, sourceENB, ueID, `{"message_type":"inject_nas","replay_last":true,"timeout_ms":4000}`)
	if got := jsonGet(resp, "s1ap.message_type"); got != "ErrorIndication" {
		t.Errorf("stale source uplink NAS: s1ap.message_type = %q, want ErrorIndication (TS 36.413 §10.6)\n  body: %s", got, resp)
	}
}

// An S1 reset resets only the resetting association's connections (TS 36.413 §8.7.1).
func Test4GPathSwitchSourceResetPreservesMovedUE(t *testing.T) {
	sourceENB := createENBWithID(t, claimENBID(), "ps-stale-reset-src")
	targetENB := createENBWithID(t, claimENBID(), "ps-stale-reset-tgt")

	ueID := mustCreateENBUE(t, sourceENB)
	fullAttach(t, sourceENB, ueID)

	mmeID := moveENBPathToTarget(t, sourceENB, targetENB, ueID, 700005)

	_, resp := doRequest(t, "POST", "/enb/"+sourceENB+"/s1ap", `{"message_type":"reset","timeout_ms":4000}`)
	if got := jsonGet(resp, "s1ap.message_type"); got != "ResetAcknowledge" {
		t.Errorf("source reset: s1ap.message_type = %q, want ResetAcknowledge (TS 36.413 §8.7.1)\n  body: %s", got, resp)
	}

	assertENBUEStillSwitchable(t, targetENB, mmeID, 700006, "UE survives a source S1 reset")
}
