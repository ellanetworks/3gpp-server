// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Handover Cancellation (TS 38.413 §8.4.5): the source gNB aborts an ongoing or
// already-prepared N2 handover with a HANDOVER CANCEL, and the AMF replies with
// HANDOVER CANCEL ACKNOWLEDGE (§8.4.5.2). Abnormal cases follow §10.6. Every
// assertion is the spec-mandated outcome, so a failure means Ella Core deviates.

package integration_test

import (
	"fmt"
	"testing"
)

// Test5GN2HandoverCancelDuringPreparation: the source cancels after the target has
// received the Handover Request but before it is acknowledged. The AMF must
// answer with HANDOVER CANCEL ACKNOWLEDGE (TS 38.413 §8.4.5.2).
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

	// Cancelling must release the resources reserved at the target: the AMF
	// sends it a UE Context Release Command (TS 38.413 §8.4.5).
	if got := jsonGet(awaitNGAP(t, targetGNB, ngapUEContextReleaseCommand), "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Errorf("after cancel, target did not receive UEContextReleaseCommand (prepared resources not released): got %q", got)
	}
}

// Test5GN2HandoverCancelAfterCommand: the source cancels after it has already
// received the Handover Command (a valid late cancel — TS 38.413 §8.4.1.3
// interaction with Handover Cancel). The AMF must still acknowledge it.
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

// Test5GN2HandoverCancelThenReHandover: after cancelling a handover, a fresh
// handover of the same UE must succeed — proving the cancel freed the handover
// procedure and the UE's resources (TS 38.413 §8.4.5).
func Test5GN2HandoverCancelThenReHandover(t *testing.T) {
	srcGNB := createGnBWithID(t, "00030a", "ho-recancel-src")
	targetGNB := createGnBWithID(t, "00030b", "ho-recancel-tgt")

	ueID := establishRegisteredUE(t, srcGNB)

	// First handover, cancelled during preparation.
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

	// Second handover of the same UE must complete.
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

// Test5GN2HandoverCancelNoHandoverInProgress: a Handover Cancel for a UE with no
// handover underway. TS 38.413 §8.4.5 defines the procedure only for an ongoing
// or prepared handover, so the response here is unspecified — but the spec
// universally requires the core not to be disturbed: the UE must stay usable.
func Test5GN2HandoverCancelNoHandoverInProgress(t *testing.T) {
	gnb := createGnBWithID(t, "00030c", "ho-nocancel")

	ueID := registerUEWithSUPI(t, gnb, "imsi-001010000000001")

	// No HANDOVER REQUIRED was sent; the AMF's response (if any) is unspecified.
	doRequest(t, "POST", "/gnb/"+gnb+"/ue/"+ueID+"/ngap", `{"message_type":"handover_cancel"}`)

	assertUEStillConnected(t, gnb, ueID)
}

// Test5GN2HandoverCancelUnknownRanUeNgapID: a Handover Cancel bearing a RAN UE
// NGAP ID the AMF never assigned carries an unknown local AP ID; §10.6 requires
// an Error Indication.
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

// Test5GN2HandoverCancelInconsistentAmfUeNgapID: a Handover Cancel whose AMF UE
// NGAP ID is inconsistent with the one stored for the UE must draw an Error
// Indication and must not be acted upon (TS 38.413 §10.6) — exactly as the AMF
// does for an inconsistent ID in Handover Required.
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
