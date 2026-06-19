// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// N2 handover edge cases built from the existing handover messages. Each feeds
// the AMF a handover message bearing an AMF UE NGAP ID it never assigned. Per
// TS 38.413 §10.6 the AMF must answer with an Error Indication carrying the
// received AP IDs — a specific required response, not merely "stay alive". A
// timeout (no Error Indication) or a crash is a conformance defect in the core.

package integration_test

import (
	"fmt"
	"testing"
)

// unknownAmfUeNgapID is far above the AMF's sequential allocation, so it never
// matches a live UE association.
const unknownAmfUeNgapID = 4294967295

// establishRegisteredUE registers a UE on the gNB and establishes its PDU
// session, returning the UE ID.
func establishRegisteredUE(t *testing.T, gnbID string) string {
	t.Helper()

	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("pdu_session_establishment_request: HTTP %d\n  body: %s", status, body)
	}

	return ueID
}

func expectErrorIndication(t *testing.T, gnbID, context string) {
	t.Helper()

	ind := awaitNGAP(t, gnbID, ngapErrorIndication)
	if got := jsonGet(ind, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("%s: message_type = %q, want ErrorIndication (TS 38.413 §10.6)\n  body: %s", context, got, ind)
	}
}

func expectHandoverPreparationFailure(t *testing.T, gnbID, context string) {
	t.Helper()

	fail := awaitNGAP(t, gnbID, ngapHandoverPreparationFailure)
	if got := jsonGet(fail, "ngap.message_type"); got != ngapHandoverPreparationFailure {
		t.Errorf("%s: message_type = %q, want HandoverPreparationFailure (TS 38.413 §8.4.1.3)\n  body: %s", context, got, fail)
	}
}

// A HANDOVER REQUIRED whose AMF UE NGAP ID is unknown carries an unknown local
// AP ID; §10.6 requires the AMF to answer the source with an Error Indication.
func TestN2HandoverRequiredUnknownAmfUeNgapID(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000003", "ho-edge-src")
	createGnBWithID(t, "000004", "ho-edge-tgt")

	ueID := establishRegisteredUE(t, sourceGNB)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_required","target_gnb_id":"000004","amf_ue_ngap_id_override":%d}`, unknownAmfUeNgapID))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, sourceGNB, "HandoverRequired with unknown AMF UE NGAP ID")
}

// A HANDOVER REQUIRED whose RAN UE NGAP ID does not match the one stored for
// the UE carries an inconsistent remote AP ID; §10.6 requires the AMF to answer
// the source with an Error Indication.
func TestN2HandoverRequiredInconsistentRanUeNgapID(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000009", "ho-edge-src")
	createGnBWithID(t, "00000a", "ho-edge-tgt")

	ueID := establishRegisteredUE(t, sourceGNB)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_required","target_gnb_id":"00000a","ran_ue_ngap_id_override":%d}`, unknownAmfUeNgapID))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, sourceGNB, "HandoverRequired with inconsistent RAN UE NGAP ID")
}

// A HANDOVER REQUIRED for a UE that never registered references a UE the AMF
// has no context for; §10.6 requires an Error Indication to the source.
func TestN2HandoverRequiredUnregisteredUE(t *testing.T) {
	sourceGNB := createGnBWithID(t, "00000b", "ho-edge-src")
	createGnBWithID(t, "00000c", "ho-edge-tgt")

	ueID := mustCreateUE(t, sourceGNB) // created but never registered

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"00000c"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, sourceGNB, "HandoverRequired for an unregistered UE")
}

// A HANDOVER REQUIRED naming a target gNB the AMF does not know is a failure
// during handover preparation; §8.4.1.3 requires the AMF to answer the source
// with a HANDOVER PREPARATION FAILURE (cause unknown-targetID).
func TestN2HandoverRequiredUnknownTarget(t *testing.T) {
	sourceGNB := createGnBWithID(t, "00000d", "ho-edge-src")

	ueID := establishRegisteredUE(t, sourceGNB)

	// Target gNB ffffff was never set up on the AMF.
	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"ffffff"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectHandoverPreparationFailure(t, sourceGNB, "HandoverRequired to an unknown target gNB")
}

// A HANDOVER REQUIRED referencing a PDU session the UE does not have leaves the
// AMF/SMF unable to prepare any resource; §8.4.1.3 requires a HANDOVER
// PREPARATION FAILURE to the source.
func TestN2HandoverRequiredUnknownPDUSession(t *testing.T) {
	sourceGNB := createGnBWithID(t, "00000e", "ho-edge-src")
	createGnBWithID(t, "00000f", "ho-edge-tgt")

	ueID := establishRegisteredUE(t, sourceGNB)

	// Session 9 was never established for this UE.
	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"00000f","pdu_session_ids":[9]}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectHandoverPreparationFailure(t, sourceGNB, "HandoverRequired for a non-existent PDU session")
}

// A HANDOVER REQUEST ACKNOWLEDGE is the first returned message of the resource
// allocation procedure; an unknown AMF UE NGAP ID in it is an unknown local AP
// ID, so §10.6 requires an Error Indication to the target.
func TestN2HandoverRequestAcknowledgeUnknownAmfUeNgapID(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000005", "ho-edge-src")
	targetGNB := createGnBWithID(t, "000006", "ho-edge-tgt")

	ueID := establishRegisteredUE(t, sourceGNB)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000006"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, targetGNB, ngapHandoverRequest), "ngap.message_type"); got != ngapHandoverRequest {
		t.Fatalf("expected HandoverRequest on target, got %q", got)
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9000,"dl_ip":"10.3.0.3"}]}`, unknownAmfUeNgapID))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, targetGNB, "HandoverRequestAcknowledge with unknown AMF UE NGAP ID")
}

// After the target's RAN UE NGAP ID is known (from a valid acknowledge), a
// HANDOVER NOTIFY bearing an unknown AMF UE NGAP ID still carries an unknown
// local AP ID, so §10.6 requires an Error Indication to the target.
func TestN2HandoverNotifyUnknownAmfUeNgapID(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000007", "ho-edge-src")
	targetGNB := createGnBWithID(t, "000008", "ho-edge-tgt")

	ueID := establishRegisteredUE(t, sourceGNB)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000008"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	targetAmfID, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9000,"dl_ip":"10.3.0.3"}]}`, targetAmfID))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, sourceGNB, ngapHandoverCommand), "ngap.message_type"); got != ngapHandoverCommand {
		t.Fatalf("expected HandoverCommand on source, got %q", got)
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_notify","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100}`, unknownAmfUeNgapID))
	if status != 200 {
		t.Fatalf("handover_notify: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, targetGNB, "HandoverNotify with unknown AMF UE NGAP ID")
}
