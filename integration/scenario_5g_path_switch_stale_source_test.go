// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// The returned AMF UE NGAP ID is unchanged by the switch; the source's AP IDs go stale.
func movePathToTarget(t *testing.T, sourceGNB, targetGNB, supi string, newRanID int64) (string, int64) {
	t.Helper()

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, supi)
	amfID, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amfID, newRanID))
	assertPathSwitchType(t, "initial path switch to target", status, body, ngapPathSwitchRequestAcknowledge)

	return ueID, amfID
}

func assertUEStillSwitchable(t *testing.T, gnbID string, amfID, newRanID int64, context string) {
	t.Helper()

	status, body := sendPathSwitch(t, gnbID,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amfID, newRanID))
	assertPathSwitchType(t, context, status, body, ngapPathSwitchRequestAcknowledge)
}

func Test5GPathSwitchStaleSourceUEContextReleaseRejected(t *testing.T) {
	sourceGNB := createGNBWithID(t, "000120", "ps-stale-rel-src")
	targetGNB := createGNBWithID(t, "000121", "ps-stale-rel-tgt")

	ueID, amfID := movePathToTarget(t, sourceGNB, targetGNB, "imsi-001010000000020", 210)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("stale source release request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("stale source UE Context Release Request: message_type = %q, want ErrorIndication (TS 38.413 §10.6)\n  body: %s", got, body)
	}

	assertUEStillSwitchable(t, targetGNB, amfID, 211, "UE survives a stale source UE Context Release Request")
}

func Test5GPathSwitchStaleSourceUplinkNASRejected(t *testing.T) {
	sourceGNB := createGNBWithID(t, "000122", "ps-stale-nas-src")
	targetGNB := createGNBWithID(t, "000123", "ps-stale-nas-tgt")

	ueID, _ := movePathToTarget(t, sourceGNB, targetGNB, "imsi-001010000000021", 212)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("stale source uplink NAS: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("stale source uplink NAS: message_type = %q, want ErrorIndication (TS 38.413 §10.6)\n  body: %s", got, body)
	}
}

// An NG Reset resets only the resetting association's connections (TS 38.413 §8.7.4).
func Test5GPathSwitchSourceNGResetPreservesMovedUE(t *testing.T) {
	sourceGNB := createGNBWithID(t, "000124", "ps-stale-reset-src")
	targetGNB := createGNBWithID(t, "000125", "ps-stale-reset-tgt")

	_, amfID := movePathToTarget(t, sourceGNB, targetGNB, "imsi-001010000000022", 213)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ngap", `{"message_type":"ng_reset"}`)
	if status != 200 {
		t.Fatalf("source ng_reset: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapNGResetAcknowledge {
		t.Errorf("source ng_reset: message_type = %q, want NGResetAcknowledge (TS 38.413 §8.7.4)\n  body: %s", got, body)
	}

	assertUEStillSwitchable(t, targetGNB, amfID, 214, "UE survives a source NG Reset")
}
