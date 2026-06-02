//go:build integration

// Handover Failure (TS 38.413 §8.4.2.3): the target gNB rejects a handover with
// a HANDOVER FAILURE, and the AMF answers the source with a HANDOVER PREPARATION
// FAILURE (§8.4.1.3). Abnormal AP-ID cases follow §10.6. Every assertion is the
// spec-mandated outcome, so a failure means Ella Core deviates.

package integration_test

import (
	"fmt"
	"testing"
)

// TestN2HandoverFailureRejection: the target rejects the prepared handover with
// a HANDOVER FAILURE; the AMF must answer the source with a HANDOVER PREPARATION
// FAILURE (TS 38.413 §8.4.2.3 → §8.4.1.3).
func TestN2HandoverFailureRejection(t *testing.T) {
	srcGNB := createGnBWithID(t, "000401", "ho-fail-src")
	targetGNB := createGnBWithID(t, "000402", "ho-fail-tgt")

	ueID := establishRegisteredUE(t, srcGNB)

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000402"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	targetAmf, ok := ngapFirstAmfUeNgapID(awaitNGAP(t, targetGNB, ngapHandoverRequest))
	if !ok {
		t.Fatal("HandoverRequest missing AMF UE NGAP ID")
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_failure","amf_ue_ngap_id":%d}`, targetAmf))
	if status != 200 {
		t.Fatalf("handover_failure: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, srcGNB, ngapHandoverPreparationFailure), "ngap.message_type"); got != ngapHandoverPreparationFailure {
		t.Errorf("after Handover Failure: source got %q, want HandoverPreparationFailure (TS 38.413 §8.4.1.3)", got)
	}
}

// TestN2HandoverFailureThenReHandover: after a handover is rejected, a fresh
// handover of the same UE must succeed — the rejection released the handover
// procedure and the UE's resources (TS 38.413 §8.4.2.3).
func TestN2HandoverFailureThenReHandover(t *testing.T) {
	srcGNB := createGnBWithID(t, "000403", "ho-refail-src")
	targetGNB := createGnBWithID(t, "000404", "ho-refail-tgt")

	ueID := establishRegisteredUE(t, srcGNB)

	// First handover, rejected by the target.
	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000404"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	targetAmf, ok := ngapFirstAmfUeNgapID(awaitNGAP(t, targetGNB, ngapHandoverRequest))
	if !ok {
		t.Fatal("HandoverRequest missing AMF UE NGAP ID")
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_failure","amf_ue_ngap_id":%d}`, targetAmf))
	if status != 200 {
		t.Fatalf("handover_failure: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, srcGNB, ngapHandoverPreparationFailure), "ngap.message_type"); got != ngapHandoverPreparationFailure {
		t.Fatalf("source got %q, want HandoverPreparationFailure", got)
	}

	// Second handover of the same UE must complete.
	status, body = doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000404"}`)
	if status != 200 {
		t.Fatalf("re-handover handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	if got := jsonGet(hoReq, "ngap.message_type"); got != ngapHandoverRequest {
		t.Fatalf("re-handover: got %q, want HandoverRequest (failure did not free the procedure)", got)
	}

	targetAmf2, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatal("re-handover HandoverRequest missing AMF UE NGAP ID")
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9000,"dl_ip":"10.3.0.3"}]}`, targetAmf2))
	if status != 200 {
		t.Fatalf("re-handover acknowledge: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, srcGNB, ngapHandoverCommand), "ngap.message_type"); got != ngapHandoverCommand {
		t.Errorf("re-handover: source got %q, want HandoverCommand", got)
	}

	completeHandover(t, targetGNB, targetAmf2, 100)
}

// TestN2HandoverFailureUnknownAmfUeNgapID: a HANDOVER FAILURE bearing an AMF UE
// NGAP ID the AMF never assigned carries an unknown local AP ID; §10.6 requires
// an Error Indication.
func TestN2HandoverFailureUnknownAmfUeNgapID(t *testing.T) {
	targetGNB := createGnBWithID(t, "000405", "ho-fail-tgt")

	status, body := doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_failure","amf_ue_ngap_id":%d}`, unknownAmfUeNgapID))
	if status != 200 {
		t.Fatalf("handover_failure: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, targetGNB, "Handover Failure with unknown AMF UE NGAP ID")
}

// TestN2HandoverFailureCrossAssociationHijack: a rogue gNB forges a HANDOVER
// FAILURE bearing a victim's AMF UE NGAP ID. The ID is unknown on the rogue's
// own association, so §10.6 requires an Error Indication there, and the victim
// must be untouched.
func TestN2HandoverFailureCrossAssociationHijack(t *testing.T) {
	victimGNB := createGnBWithID(t, "000406", "victim-gnb")
	attackerGNB := createGnBWithID(t, "000407", "attacker-gnb")

	victimUE := registerUEWithSUPI(t, victimGNB, "imsi-001010000000001")
	victimAmf, _ := ueNGAPIDs(t, victimGNB, victimUE)

	status, body := doRequest(t, "POST", "/gnb/"+attackerGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_failure","amf_ue_ngap_id":%d}`, victimAmf))
	if status != 200 {
		t.Fatalf("forged handover_failure: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, attackerGNB, "forged Handover Failure with victim's AMF UE NGAP ID")
	assertUEStillConnected(t, victimGNB, victimUE)
}
