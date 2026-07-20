// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test5GN2HandoverFailureRejection(t *testing.T) {
	srcGNB := createGNBWithID(t, "000401", "ho-fail-src")
	targetGNB := createGNBWithID(t, "000402", "ho-fail-tgt")

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

	prepFail := awaitNGAP(t, srcGNB, ngapHandoverPreparationFailure)
	if got := jsonGet(prepFail, "ngap.message_type"); got != ngapHandoverPreparationFailure {
		t.Errorf("after Handover Failure: source got %q, want HandoverPreparationFailure (TS 38.413 §8.4.1.3)", got)
	}

	if !ngapHasCause(prepFail) {
		t.Errorf("HandoverPreparationFailure missing mandatory Cause (TS 38.413 §9.2.3.3)\n  body: %s", prepFail)
	}
}

func Test5GN2HandoverFailureThenReHandover(t *testing.T) {
	srcGNB := createGNBWithID(t, "000403", "ho-refail-src")
	targetGNB := createGNBWithID(t, "000404", "ho-refail-tgt")

	ueID := establishRegisteredUE(t, srcGNB)

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

func Test5GN2HandoverFailureUnknownAmfUeNgapID(t *testing.T) {
	targetGNB := createGNBWithID(t, "000405", "ho-fail-tgt")

	status, body := doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_failure","amf_ue_ngap_id":%d}`, unknownAmfUeNgapID))
	if status != 200 {
		t.Fatalf("handover_failure: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, targetGNB, "Handover Failure with unknown AMF UE NGAP ID")
}

func Test5GN2HandoverFailureCrossAssociationHijack(t *testing.T) {
	victimGNB := createGNBWithID(t, "000406", "victim-gnb")
	attackerGNB := createGNBWithID(t, "000407", "attacker-gnb")

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
