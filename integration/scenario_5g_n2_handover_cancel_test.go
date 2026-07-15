// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test5GN2HandoverCancelDuringPreparation(t *testing.T) {
	srcGNB := createGnBWithID(t, "000301", "ho-cancel-src")
	targetGNB := createGnBWithID(t, "000302", "ho-cancel-tgt")

	ueID := establishRegisteredUE(t, srcGNB)

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000302"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, targetGNB, ngapHandoverRequest), "ngap.message_type"); got != ngapHandoverRequest {
		t.Fatalf("expected HandoverRequest on target, got %q", got)
	}

	status, body = doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_cancel"}`)
	if status != 200 {
		t.Fatalf("handover_cancel: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapHandoverCancelAcknowledge {
		t.Errorf("handover_cancel during preparation: ngap.message_type = %q, want HandoverCancelAcknowledge (TS 38.413 §8.4.5.2)\n  body: %s", got, body)
	}

	if got := jsonGet(awaitNGAP(t, targetGNB, ngapUEContextReleaseCommand), "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Errorf("after cancel, target did not receive UEContextReleaseCommand (prepared resources not released): got %q", got)
	}
}

func Test5GN2HandoverCancelAfterCommand(t *testing.T) {
	srcGNB := createGnBWithID(t, "000303", "ho-cancel-src")
	targetGNB := createGnBWithID(t, "000304", "ho-cancel-tgt")

	ueID := establishRegisteredUE(t, srcGNB)

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000304"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	targetAmf, ok := ngapFirstAmfUeNgapID(awaitNGAP(t, targetGNB, ngapHandoverRequest))
	if !ok {
		t.Fatal("HandoverRequest missing AMF UE NGAP ID")
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9000,"dl_ip":"10.3.0.3"}]}`, targetAmf))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, srcGNB, ngapHandoverCommand), "ngap.message_type"); got != ngapHandoverCommand {
		t.Fatalf("expected HandoverCommand on source, got %q", got)
	}

	status, body = doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_cancel"}`)
	if status != 200 {
		t.Fatalf("handover_cancel: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapHandoverCancelAcknowledge {
		t.Errorf("handover_cancel after command: ngap.message_type = %q, want HandoverCancelAcknowledge (TS 38.413 §8.4.5.2)\n  body: %s", got, body)
	}
}

func Test5GN2HandoverCancelThenReHandover(t *testing.T) {
	srcGNB := createGnBWithID(t, "00030a", "ho-recancel-src")
	targetGNB := createGnBWithID(t, "00030b", "ho-recancel-tgt")

	ueID := establishRegisteredUE(t, srcGNB)

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"00030b"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, targetGNB, ngapHandoverRequest), "ngap.message_type"); got != ngapHandoverRequest {
		t.Fatalf("expected HandoverRequest on target, got %q", got)
	}

	status, body = doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap", `{"message_type":"handover_cancel"}`)
	if status != 200 {
		t.Fatalf("handover_cancel: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapHandoverCancelAcknowledge {
		t.Fatalf("handover_cancel: ngap.message_type = %q, want HandoverCancelAcknowledge", got)
	}

	status, body = doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"00030b"}`)
	if status != 200 {
		t.Fatalf("re-handover handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	if got := jsonGet(hoReq, "ngap.message_type"); got != ngapHandoverRequest {
		t.Fatalf("re-handover: expected HandoverRequest (cancel did not free the procedure), got %q", got)
	}

	targetAmf, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("re-handover HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9000,"dl_ip":"10.3.0.3"}]}`, targetAmf))
	if status != 200 {
		t.Fatalf("re-handover acknowledge: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, srcGNB, ngapHandoverCommand), "ngap.message_type"); got != ngapHandoverCommand {
		t.Errorf("re-handover: expected HandoverCommand on source, got %q", got)
	}

	completeHandover(t, targetGNB, targetAmf, 100)
}

// TS 38.413 §8.4.5 defines Handover Cancel only for an ongoing or prepared
// handover, so with none underway only the UE staying usable is asserted.
func Test5GN2HandoverCancelNoHandoverInProgress(t *testing.T) {
	gnb := createGnBWithID(t, "00030c", "ho-nocancel")

	ueID := registerUEWithSUPI(t, gnb, "imsi-001010000000001")

	doRequest(t, "POST", "/gnb/"+gnb+"/ue/"+ueID+"/ngap", `{"message_type":"handover_cancel"}`)

	assertUEStillConnected(t, gnb, ueID)
}

func Test5GN2HandoverCancelUnknownRanUeNgapID(t *testing.T) {
	srcGNB := createGnBWithID(t, "000305", "ho-cancel-src")

	ueID := establishRegisteredUE(t, srcGNB)

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_cancel","ran_ue_ngap_id_override":%d}`, unknownAmfUeNgapID))
	if status != 200 {
		t.Fatalf("handover_cancel: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("handover_cancel with unknown RAN UE NGAP ID: ngap.message_type = %q, want ErrorIndication (TS 38.413 §10.6)\n  body: %s", got, body)
	}
}

func Test5GN2HandoverCancelInconsistentAmfUeNgapID(t *testing.T) {
	srcGNB := createGnBWithID(t, "000306", "ho-cancel-src")
	targetGNB := createGnBWithID(t, "000307", "ho-cancel-tgt")

	ueID := establishRegisteredUE(t, srcGNB)

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000307"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, targetGNB, ngapHandoverRequest), "ngap.message_type"); got != ngapHandoverRequest {
		t.Fatalf("expected HandoverRequest on target, got %q", got)
	}

	status, body = doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_cancel","amf_ue_ngap_id_override":%d}`, unknownAmfUeNgapID))
	if status != 200 {
		t.Fatalf("handover_cancel: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("handover_cancel with inconsistent AMF UE NGAP ID: ngap.message_type = %q, want ErrorIndication (TS 38.413 §10.6)\n  body: %s", got, body)
	}
}
