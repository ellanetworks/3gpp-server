// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// N2 handover scenarios involving more than one PDU session and the follow-on
// mobility registration (TS 38.413 §8.4, TS 23.502 §4.9.1.3). These assert the
// concrete messages the AMF must produce, not merely that it stays alive.

package integration_test

import (
	"fmt"
	"testing"
)

// completeHandover sends the Handover Notify that finishes the procedure, so
// the UE is left in a clean state on the target (avoiding cross-test residue).
func completeHandover(t *testing.T, targetGNB string, amfUeNgapID, ranUeNgapID int64) {
	t.Helper()

	status, body := doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_notify","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d}`, amfUeNgapID, ranUeNgapID))
	if status != 200 {
		t.Fatalf("handover_notify: HTTP %d\n  body: %s", status, body)
	}
}

// establishPDUSession establishes a specific PDU session for a UE.
func establishPDUSession(t *testing.T, gnbID, ueID string, sessionID int) {
	t.Helper()

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_establishment_request","pdu_session_id":%d}`, sessionID))
	if status != 200 {
		t.Fatalf("establish PDU session %d: HTTP %d\n  body: %s", sessionID, status, body)
	}
}

// TestN2HandoverMultiplePDUSessions hands over a UE holding two PDU sessions.
// The AMF must request both at the target (§9.2.3.1) and confirm both in the
// Handover Command (§9.2.3.2).
func TestN2HandoverMultiplePDUSessions(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000011", "ho-multi-src")
	targetGNB := createGnBWithID(t, "000012", "ho-multi-tgt")

	ueID := establishRegisteredUE(t, sourceGNB) // session 1
	establishPDUSession(t, sourceGNB, ueID, 2)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000012","pdu_session_ids":[1,2]}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	assertCarriesPDUSessions(t, hoReq, []int64{1, 2}, "HandoverRequest")

	targetAmfID, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"},{"id":2,"dl_teid":9002,"dl_ip":"10.3.0.3"}]}`, targetAmfID))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	hoCmd := awaitNGAP(t, sourceGNB, ngapHandoverCommand)
	assertCarriesPDUSessions(t, hoCmd, []int64{1, 2}, "HandoverCommand")

	completeHandover(t, targetGNB, targetAmfID, 100)
}

// TestN2HandoverPartialAdmission hands over two PDU sessions but the target
// admits only one. Per §8.4.2.2/§8.4.1.2 the AMF must confirm the admitted
// session in the Handover List and place the non-admitted one in the PDU
// Session Resource To Release List of the Handover Command.
func TestN2HandoverPartialAdmission(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000013", "ho-part-src")
	targetGNB := createGnBWithID(t, "000014", "ho-part-tgt")

	ueID := establishRegisteredUE(t, sourceGNB) // session 1
	establishPDUSession(t, sourceGNB, ueID, 2)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000014","pdu_session_ids":[1,2]}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	assertCarriesPDUSessions(t, hoReq, []int64{1, 2}, "HandoverRequest")

	targetAmfID, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	// Admit session 1, fail session 2.
	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"}],"failed_pdu_sessions":[2]}`, targetAmfID))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	hoCmd := awaitNGAP(t, sourceGNB, ngapHandoverCommand)
	assertCarriesPDUSessions(t, hoCmd, []int64{1}, "HandoverCommand admitted")

	if rel := ngapReleasePDUSessionIDs(hoCmd); !sameInt64Set(rel, []int64{2}) {
		t.Errorf("HandoverCommand to-release list = %v, want [2] (TS 38.413 §8.4.1.2)\n  body: %s", rel, hoCmd)
	}

	completeHandover(t, targetGNB, targetAmfID, 100)
}

// TestN2HandoverMobilityRegistrationUpdate completes an N2 handover, then has
// the UE perform a Mobility Registration Update on the target over its existing
// connection — the Registration Procedure of TS 23.502 §4.9.1.3.3 step 12. The
// AMF must accept it with a Registration Accept (TS 24.501 §5.5.1.3), reusing
// the migrated security context.
func TestN2HandoverMobilityRegistrationUpdate(t *testing.T) {
	sourceGNB := createGnBWithID(t, "000015", "ho-mru-src")
	targetGNB := createGnBWithID(t, "000016", "ho-mru-tgt")

	ueID := establishRegisteredUE(t, sourceGNB)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000016"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	targetAmfID, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	const targetRanUeNgapID = 100
	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"}]}`, targetAmfID, targetRanUeNgapID))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, sourceGNB, ngapHandoverCommand), "ngap.message_type"); got != ngapHandoverCommand {
		t.Fatalf("expected HandoverCommand on source, got %q", got)
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_notify","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d}`, targetAmfID, targetRanUeNgapID))
	if status != 200 {
		t.Fatalf("handover_notify: HTTP %d\n  body: %s", status, body)
	}

	// The UE now lives on the target with the target-side NGAP IDs.
	status, body = doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/migrate",
		fmt.Sprintf(`{"target_gnb_id":"%s","ran_ue_ngap_id":%d,"amf_ue_ngap_id":%d}`, targetGNB, targetRanUeNgapID, targetAmfID))
	if status != 200 {
		t.Fatalf("migrate UE: HTTP %d\n  body: %s", status, body)
	}

	// Mobility Registration Update over the existing connection.
	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request","registration_type":2,"existing_connection":true}`)
	if status != 200 {
		t.Fatalf("mobility registration update: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasRegistrationAccept {
		t.Errorf("mobility registration update: nas.message_type = %q, want registration_accept (TS 24.501 §5.5.1.3)\n  body: %s", got, body)
	}
}
