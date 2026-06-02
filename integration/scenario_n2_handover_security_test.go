//go:build integration

// Adversarial N2 handover scenarios: a rogue or compromised gNB abusing the
// handover messages to hijack, confuse, or exhaust the AMF. Where TS 38.413
// defines a response (e.g. §10.6 → Error Indication) the test asserts it; where
// the abnormal clause is Void (e.g. §8.4.3.3) it asserts the core neither
// crashes nor acts on the forged message (the legitimate UE stays usable).

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

// mustCreateUEWithSUPI creates a UE with a specific subscriber identity.
func mustCreateUEWithSUPI(t *testing.T, gnbID, supi string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"supi": "%s",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": "internet",
		"routing_indicator": "0", "protection_scheme": "0", "public_key_id": "0",
		"imeisv": "1122334455667788"
	}`, supi)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create ue %s: HTTP %d: %s", supi, status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	if ueID == "" {
		t.Fatalf("create ue %s: no ue_id in response", supi)
	}

	return ueID
}

// registerUEWithSUPI creates and registers a UE with a specific identity.
func registerUEWithSUPI(t *testing.T, gnbID, supi string) string {
	t.Helper()

	ueID := mustCreateUEWithSUPI(t, gnbID, supi)
	doRegistrationFlow(t, gnbID, ueID)

	return ueID
}

// ueNGAPIDs returns the AMF and RAN UE NGAP IDs the AMF assigned to a UE.
func ueNGAPIDs(t *testing.T, gnbID, ueID string) (amf, ran int64) {
	t.Helper()

	status, body := doRequest(t, "GET", "/gnb/"+gnbID+"/ue/"+ueID, "")
	if status != 200 {
		t.Fatalf("get ue state: HTTP %d\n  body: %s", status, body)
	}

	var st struct {
		AmfUeNgapID int64 `json:"amf_ue_ngap_id"`
		RanUeNgapID int64 `json:"ran_ue_ngap_id"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("decode ue state: %v\n  body: %s", err, body)
	}

	return st.AmfUeNgapID, st.RanUeNgapID
}

// assertUEStillConnected fails unless the UE can still complete a UE-associated
// transaction — used after an attack to prove the core did not act on the
// forged message and tear the victim down.
func assertUEStillConnected(t *testing.T, gnbID, ueID string) {
	t.Helper()

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Errorf("victim no longer usable after the attack (HTTP %d) — core may have acted on the forged message\n  body: %s", status, body)
	}
}

func containsInt64(ids []int64, want int64) bool {
	for _, v := range ids {
		if v == want {
			return true
		}
	}

	return false
}

// TestN2HandoverAcknowledgeCrossAssociationHijack: a rogue gNB forges a Handover
// Request Acknowledge bearing a victim UE's AMF UE NGAP ID. The ID is unknown on
// the rogue's own association, so §10.6 requires an Error Indication there, and
// the victim (on another gNB) must be untouched.
func TestN2HandoverAcknowledgeCrossAssociationHijack(t *testing.T) {
	victimGNB := createGnBWithID(t, "0000a0", "victim-gnb")
	attackerGNB := createGnBWithID(t, "0000a1", "attacker-gnb")

	victimUE := registerUEWithSUPI(t, victimGNB, "imsi-001010000000001")
	victimAmf, _ := ueNGAPIDs(t, victimGNB, victimUE)

	status, body := doRequest(t, "POST", "/gnb/"+attackerGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"}]}`, victimAmf))
	if status != 200 {
		t.Fatalf("forged acknowledge: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, attackerGNB, "forged HandoverRequestAcknowledge with victim's AMF UE NGAP ID")
	assertUEStillConnected(t, victimGNB, victimUE)
}

// TestN2HandoverNotifyCrossAssociationHijack: same hijack via a forged Handover
// Notify.
func TestN2HandoverNotifyCrossAssociationHijack(t *testing.T) {
	victimGNB := createGnBWithID(t, "0000a2", "victim-gnb")
	attackerGNB := createGnBWithID(t, "0000a3", "attacker-gnb")

	victimUE := registerUEWithSUPI(t, victimGNB, "imsi-001010000000001")
	victimAmf, _ := ueNGAPIDs(t, victimGNB, victimUE)

	status, body := doRequest(t, "POST", "/gnb/"+attackerGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_notify","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100}`, victimAmf))
	if status != 200 {
		t.Fatalf("forged notify: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, attackerGNB, "forged HandoverNotify with victim's AMF UE NGAP ID")
	assertUEStillConnected(t, victimGNB, victimUE)
}

// TestN2HandoverRequiredCrossAssociationHijack: an attacker's own UE sends a
// Handover Required claiming the victim's AMF UE NGAP ID. It is inconsistent
// with the attacker association's stored ID, so §10.6 requires an Error
// Indication; the victim must be untouched.
func TestN2HandoverRequiredCrossAssociationHijack(t *testing.T) {
	victimGNB := createGnBWithID(t, "0000a4", "victim-gnb")
	attackerGNB := createGnBWithID(t, "0000a5", "attacker-gnb")

	victimUE := registerUEWithSUPI(t, victimGNB, "imsi-001010000000001")
	victimAmf, _ := ueNGAPIDs(t, victimGNB, victimUE)

	attackerUE := registerUEWithSUPI(t, attackerGNB, "imsi-001010000000002")

	status, body := doRequest(t, "POST", "/gnb/"+attackerGNB+"/ue/"+attackerUE+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_required","target_gnb_id":"0000a4","amf_ue_ngap_id_override":%d}`, victimAmf))
	if status != 200 {
		t.Fatalf("forged handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectErrorIndication(t, attackerGNB, "forged HandoverRequired with victim's AMF UE NGAP ID")
	assertUEStillConnected(t, victimGNB, victimUE)
}

// TestN2HandoverNotifyPrematureNoHandover sends a Handover Notify for a UE that
// is not being handed over. §8.4.3.3 is Void, so there is no defined response;
// the core must not crash or tear the UE down.
func TestN2HandoverNotifyPrematureNoHandover(t *testing.T) {
	gnb := createGnBWithID(t, "0000a7", "ho-premature")

	ueID := registerUEWithSUPI(t, gnb, "imsi-001010000000001")
	amf, ran := ueNGAPIDs(t, gnb, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnb+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_notify","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d}`, amf, ran))
	if status != 200 {
		t.Fatalf("premature notify: HTTP %d\n  body: %s", status, body)
	}

	assertUEStillConnected(t, gnb, ueID)
}

// TestN2HandoverAcknowledgeNonRequestedSession: the target admits a PDU session
// the AMF never asked it to set up. The AMF has no context for it, so the
// Handover Command must confirm only the genuinely-requested session.
func TestN2HandoverAcknowledgeNonRequestedSession(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000a8", "ho-extra-src")
	targetGNB := createGnBWithID(t, "0000a9", "ho-extra-tgt")

	ueID := establishRegisteredUE(t, sourceGNB) // session 1 only

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"0000a9"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	assertCarriesPDUSessions(t, hoReq, []int64{1}, "HandoverRequest")

	targetAmf, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	// Admit the requested session 1 plus an unrequested session 2.
	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"},{"id":2,"dl_teid":9002,"dl_ip":"10.3.0.3"}]}`, targetAmf))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	hoCmd := awaitNGAP(t, sourceGNB, ngapHandoverCommand)
	assertCarriesPDUSessions(t, hoCmd, []int64{1}, "HandoverCommand confirms only the requested session")

	completeHandover(t, targetGNB, targetAmf, 100)
}

// TestN2HandoverAcknowledgeDuplicateSessions: the target admits the same PDU
// session twice. The core must handle the duplicate without crashing and still
// produce a Handover Command for the session.
func TestN2HandoverAcknowledgeDuplicateSessions(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000aa", "ho-dup-src")
	targetGNB := createGnBWithID(t, "0000ab", "ho-dup-tgt")

	ueID := establishRegisteredUE(t, sourceGNB)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"0000ab"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	targetAmf, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"},{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"}]}`, targetAmf))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	hoCmd := awaitNGAP(t, sourceGNB, ngapHandoverCommand)
	if !containsInt64(ngapPDUSessionIDs(hoCmd), 1) {
		t.Errorf("HandoverCommand missing session 1 after duplicate admit\n  body: %s", hoCmd)
	}

	completeHandover(t, targetGNB, targetAmf, 100)
}

// TestN2HandoverRequiredUnknownTargetFlood fires repeated Handover Required to
// an unknown target. Each must draw a Handover Preparation Failure and free the
// handover procedure (TS 38.413 §8.4.1.3); a legitimate handover must still
// work afterwards — guarding against a procedure-state leak.
func TestN2HandoverRequiredUnknownTargetFlood(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000ac", "ho-flood-src")
	targetGNB := createGnBWithID(t, "0000ad", "ho-flood-tgt")

	ueID := establishRegisteredUE(t, sourceGNB)

	for i := 0; i < 4; i++ {
		status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
			`{"message_type":"handover_required","target_gnb_id":"ffffff"}`)
		if status != 200 {
			t.Fatalf("handover_required #%d: HTTP %d\n  body: %s", i, status, body)
		}

		expectHandoverPreparationFailure(t, sourceGNB, fmt.Sprintf("unknown-target handover_required #%d", i))
	}

	// The procedure must be free for a real handover to a known target.
	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"0000ad"}`)
	if status != 200 {
		t.Fatalf("legitimate handover_required: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, targetGNB, ngapHandoverRequest), "ngap.message_type"); got != ngapHandoverRequest {
		t.Fatalf("legitimate handover after flood produced %q, want HandoverRequest (procedure may be stuck)", got)
	}
}

// TestN2HandoverToSelf points the Handover Required at the source gNB itself.
// The behaviour is not crisply specified; the core must not crash.
func TestN2HandoverToSelf(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000ae", "ho-self")

	ueID := establishRegisteredUE(t, sourceGNB)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"0000ae"}`)
	if status != 200 {
		t.Fatalf("handover_required to self: HTTP %d\n  body: %s", status, body)
	}

	// Liveness: the core must still serve a fresh association.
	createGnBWithID(t, "0000af", "ho-self-probe")
}

// TestN2HandoverRequiredDuplicateInProgress fires a second identical Handover
// Required while the first is still being prepared. The duplicate must not
// corrupt the in-progress handover, which must still complete.
func TestN2HandoverRequiredDuplicateInProgress(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000b0", "ho-rep-src")
	targetGNB := createGnBWithID(t, "0000b1", "ho-rep-tgt")

	ueID := establishRegisteredUE(t, sourceGNB)

	for i := 0; i < 2; i++ {
		status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
			`{"message_type":"handover_required","target_gnb_id":"0000b1"}`)
		if status != 200 {
			t.Fatalf("handover_required #%d: HTTP %d\n  body: %s", i, status, body)
		}
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	targetAmf, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	status, body := doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"}]}`, targetAmf))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, sourceGNB, ngapHandoverCommand), "ngap.message_type"); got != ngapHandoverCommand {
		t.Fatalf("duplicate-in-progress: expected HandoverCommand, got %q", got)
	}

	completeHandover(t, targetGNB, targetAmf, 100)
}

// establishRegisteredUEWithSUPI registers a specific subscriber and establishes
// its PDU session.
func establishRegisteredUEWithSUPI(t *testing.T, gnbID, supi string) string {
	t.Helper()

	ueID := registerUEWithSUPI(t, gnbID, supi)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("establish PDU for %s: HTTP %d\n  body: %s", supi, status, body)
	}

	return ueID
}

// TestN2HandoverAcknowledgeMalformedTransfer feeds the AMF a Handover Request
// Acknowledge whose admitted-session transfer is malformed. The SMF cannot parse
// it (this is the class of input that once crashed it), so the session cannot be
// prepared and the AMF answers the source with a Handover Preparation Failure
// (TS 38.413 §8.4.1.3) — without crashing.
func TestN2HandoverAcknowledgeMalformedTransfer(t *testing.T) {
	cases := []struct {
		name     string
		transfer string
		supi     string
	}{
		{"garbage", "deadbeef", "imsi-001010000000001"},
		{"single byte", "00", "imsi-001010000000002"},
		{"all ones", "ffffffffffffffff", "imsi-001010000000003"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srcGNB := createGnBWithID(t, fmt.Sprintf("0002a%d", i), "ho-mal-src")
			tgtHex := fmt.Sprintf("0002b%d", i)
			targetGNB := createGnBWithID(t, tgtHex, "ho-mal-tgt")

			ueID := establishRegisteredUEWithSUPI(t, srcGNB, tc.supi)

			status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
				fmt.Sprintf(`{"message_type":"handover_required","target_gnb_id":"%s"}`, tgtHex))
			if status != 200 {
				t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
			}

			hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
			targetAmf, ok := ngapFirstAmfUeNgapID(hoReq)
			if !ok {
				t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
			}

			status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
				fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"raw_transfer":"%s"}]}`, targetAmf, tc.transfer))
			if status != 200 {
				t.Fatalf("acknowledge: HTTP %d\n  body: %s", status, body)
			}

			expectHandoverPreparationFailure(t, srcGNB, "malformed admitted transfer ("+tc.name+")")
		})
	}
}

// TestUEContextReleaseRequestCrossAssociationHijack: a rogue gNB forges a UE
// Context Release Request bearing a victim's NGAP IDs, attempting to force-drop
// the victim. The IDs are unknown on the rogue association, so §10.6 requires an
// Error Indication there, and the victim must stay connected.
func TestUEContextReleaseRequestCrossAssociationHijack(t *testing.T) {
	victimGNB := createGnBWithID(t, "0002c0", "victim-gnb")
	attackerGNB := createGnBWithID(t, "0002c1", "attacker-gnb")

	victimUE := registerUEWithSUPI(t, victimGNB, "imsi-001010000000001")
	victimAmf, victimRan := ueNGAPIDs(t, victimGNB, victimUE)

	attackerUE := registerUEWithSUPI(t, attackerGNB, "imsi-001010000000002")

	status, body := doRequest(t, "POST", "/gnb/"+attackerGNB+"/ue/"+attackerUE+"/ngap",
		fmt.Sprintf(`{"message_type":"ue_context_release_request","amf_ue_ngap_id_override":%d,"ran_ue_ngap_id_override":%d}`, victimAmf, victimRan))
	if status != 200 {
		t.Fatalf("forged release request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("forged release request: ngap.message_type = %q, want ErrorIndication (TS 38.413 §10.6)\n  body: %s", got, body)
	}

	assertUEStillConnected(t, victimGNB, victimUE)
}

func runInvalidPDUSessionHandover(t *testing.T, srcHex, tgtHex string, sessionID int) {
	t.Helper()

	srcGNB := createGnBWithID(t, srcHex, "ho-badid-src")
	createGnBWithID(t, tgtHex, "ho-badid-tgt")

	ueID := establishRegisteredUE(t, srcGNB)

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_required","target_gnb_id":"%s","pdu_session_ids":[%d]}`, tgtHex, sessionID))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	expectHandoverPreparationFailure(t, srcGNB, fmt.Sprintf("handover_required with invalid PDU session id %d", sessionID))
}

// TestN2HandoverRequiredInvalidPDUSessionID: a Handover Required referencing an
// out-of-range PDU session ID (valid range is 1..15) has nothing preparable, so
// the AMF answers with a Handover Preparation Failure (TS 38.413 §8.4.1.3).
func TestN2HandoverRequiredInvalidPDUSessionID(t *testing.T) {
	t.Run("session-0", func(t *testing.T) { runInvalidPDUSessionHandover(t, "0002d0", "0002d1", 0) })
	t.Run("session-16", func(t *testing.T) { runInvalidPDUSessionHandover(t, "0002d2", "0002d3", 16) })
}

// TestN2HandoverRequiredManyPDUSessions: a Handover Required listing many PDU
// sessions, most of which the UE does not hold, must be handled gracefully — the
// AMF prepares only the genuinely-established session.
func TestN2HandoverRequiredManyPDUSessions(t *testing.T) {
	srcGNB := createGnBWithID(t, "0002e0", "ho-many-src")
	tgtHex := "0002e1"
	targetGNB := createGnBWithID(t, tgtHex, "ho-many-tgt")

	ueID := establishRegisteredUE(t, srcGNB) // only session 1 exists

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_required","target_gnb_id":"%s","pdu_session_ids":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]}`, tgtHex))
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	assertCarriesPDUSessions(t, hoReq, []int64{1}, "HandoverRequest prepares only the established session")

	targetAmf, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":100,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"}]}`, targetAmf))
	if status != 200 {
		t.Fatalf("acknowledge: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, srcGNB, ngapHandoverCommand), "ngap.message_type"); got != ngapHandoverCommand {
		t.Fatalf("expected HandoverCommand, got %q", got)
	}

	completeHandover(t, targetGNB, targetAmf, 100)
}
