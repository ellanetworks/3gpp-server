//go:build integration

// State after an Xn handover: once a path switch moves a UE context to the
// target NG-RAN node, the source node holds stale AP IDs. TS 38.413 §10.6
// requires the AMF to reject UE-associated messages bearing those stale IDs with
// an Error Indication, and — critically — not to act on them, so a stale or
// rogue source cannot tear down or disturb the UE that now lives on the target.

package integration_test

import (
	"fmt"
	"testing"
)

// movePathToTarget registers a UE with a PDU session on sourceGNB, then path-
// switches it to targetGNB. Afterwards the AMF holds the UE on targetGNB and the
// source's stored AP IDs are stale. Returns the source UE id and the (unchanged)
// AMF UE NGAP ID.
func movePathToTarget(t *testing.T, sourceGNB, targetGNB, supi string, newRanID int64) (string, int64) {
	t.Helper()

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, supi)
	amfID, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amfID, newRanID))
	assertPathSwitchType(t, "initial path switch to target", status, body, ngapPathSwitchRequestAcknowledge)

	return ueID, amfID
}

// assertUEStillSwitchable proves the UE context still exists (was not torn down)
// by path-switching it again from gnbID and expecting an acknowledge.
func assertUEStillSwitchable(t *testing.T, gnbID string, amfID, newRanID int64, context string) {
	t.Helper()

	status, body := sendPathSwitch(t, gnbID,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amfID, newRanID))
	assertPathSwitchType(t, context, status, body, ngapPathSwitchRequestAcknowledge)
}

// TestPathSwitchStaleSourceUEContextReleaseRejected — §10.6: after the UE has
// switched to the target, a UE Context Release Request from the source (bearing
// the stale RAN UE NGAP ID) must be answered with an Error Indication, and must
// not release the UE that now lives on the target.
func TestPathSwitchStaleSourceUEContextReleaseRejected(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000120", "ps-stale-rel-src")
	targetGNB := createGnBWithID(t, "000121", "ps-stale-rel-tgt")

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

// TestPathSwitchStaleSourceUplinkNASRejected — §10.6: a NAS uplink from the
// stale source association carries the old AP IDs and must be answered with an
// Error Indication rather than served.
func TestPathSwitchStaleSourceUplinkNASRejected(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000122", "ps-stale-nas-src")
	targetGNB := createGnBWithID(t, "000123", "ps-stale-nas-tgt")

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

// TestPathSwitchSourceNGResetPreservesMovedUE — §8.7.4: an NG Reset resets only
// the connections on the resetting association. After the UE has switched to the
// target, a full NG Reset from the source must not release it.
func TestPathSwitchSourceNGResetPreservesMovedUE(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000124", "ps-stale-reset-src")
	targetGNB := createGnBWithID(t, "000125", "ps-stale-reset-tgt")

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
