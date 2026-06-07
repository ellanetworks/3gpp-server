//go:build integration

// Path Switch Request (Xn-handover) procedural conformance: normal operation,
// partial/total failure, and abnormal inputs (TS 38.413 §8.4.4, §9.2.3.9–10).
// A path switch is the NGAP side of an Xn handover — the AMF switches a UE
// context's downlink path to the requesting NG-RAN node. These tests assert the
// concrete messages and IEs the AMF must produce, and fail if the core does not
// conform.

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

// sendPathSwitch sends a PATH SWITCH REQUEST built from the given JSON fields
// (everything between message_type and the wait/timeout), blocking for the AMF's
// acknowledge, failure, or an error indication.
func sendPathSwitch(t *testing.T, gnbID, fields string) (int, []byte) {
	t.Helper()

	body := `{"message_type":"path_switch_request",` + fields +
		`,"wait_for":["PathSwitchRequestAcknowledge","PathSwitchRequestFailure","ErrorIndication"],"timeout_ms":5000}`

	return doRequest(t, "POST", "/gnb/"+gnbID+"/ngap", body)
}

// assertPathSwitchType fails unless the path switch produced an HTTP 200 whose
// decoded NGAP message type matches want.
func assertPathSwitchType(t *testing.T, ctx string, status int, body []byte, want string) {
	t.Helper()

	if status != 200 {
		t.Errorf("%s: HTTP %d, want a 200 carrying %s\n  body: %s", ctx, status, want, body)
		return
	}

	if got := jsonGet(body, "ngap.message_type"); got != want {
		t.Errorf("%s: message_type = %q, want %s\n  body: %s", ctx, got, want, body)
	}
}

// ngapReleasedPDUSessionIDs collects the PDU Session IDs carried by a PDU
// Session Resource Released List across the IEs of an NGAP response.
func ngapReleasedPDUSessionIDs(body []byte) []int64 {
	var top struct {
		NGAP struct {
			IEs []struct {
				ReleasePDUSessionIDs []int64 `json:"release_pdu_session_ids"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	var ids []int64
	for _, ie := range top.NGAP.IEs {
		ids = append(ids, ie.ReleasePDUSessionIDs...)
	}

	return ids
}

// TestPathSwitchRequestUnknownUEFails — §8.4.4: a path switch whose Source AMF
// UE NGAP ID matches no UE context must be answered with a Path Switch Request
// Failure.
func TestPathSwitchRequestUnknownUEFails(t *testing.T) {
	gnb := createGnBWithID(t, "0000e0", "ps-unknown")

	status, body := sendPathSwitch(t, gnb,
		`"amf_ue_ngap_id":987654,"ran_ue_ngap_id":300,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`)
	assertPathSwitchType(t, "path switch for unknown AMF UE NGAP ID", status, body, ngapPathSwitchRequestFailure)
}

// TestPathSwitchRequestNoSwitchableSessionFails — §8.4.4.3: if the 5GC fails to
// switch all requested PDU sessions (here the request names a session the UE
// does not hold), the AMF must send a Path Switch Request Failure, leaving the
// UE context intact.
func TestPathSwitchRequestNoSwitchableSessionFails(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000e1", "ps-none-src")
	targetGNB := createGnBWithID(t, "0000e2", "ps-none-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000001") // holds session 1
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":301,"pdu_sessions":[{"id":5,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))
	assertPathSwitchType(t, "path switch naming a non-held PDU session", status, body, ngapPathSwitchRequestFailure)

	assertUEStillConnected(t, sourceGNB, ueID)
}

// TestPathSwitchRequestFailureReportsReleasedSessions — §9.2.3.10 / §8.4.4.3:
// the Path Switch Request Failure must carry a PDU Session Resource Released
// List naming the PDU session(s) that could not be switched, so the NG-RAN node
// knows which to release.
func TestPathSwitchRequestFailureReportsReleasedSessions(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000e3", "ps-rel-src")
	targetGNB := createGnBWithID(t, "0000e4", "ps-rel-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000002") // holds session 1
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":302,"pdu_sessions":[{"id":5,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))

	assertPathSwitchType(t, "all-fail path switch", status, body, ngapPathSwitchRequestFailure)

	if released := ngapReleasedPDUSessionIDs(body); len(released) == 0 {
		t.Errorf("Path Switch Request Failure carries no PDU Session Resource Released List; it must name the "+
			"session(s) that failed to switch so the NG-RAN node can release them (TS 38.413 §9.2.3.10, §8.4.4.3)\n  body: %s", body)
	}
}

// TestPathSwitchRequestMultipleSessions — §8.4.4.2: a path switch listing
// several held PDU sessions switches all of them and acknowledges, with each
// session present in the PDU Session Resource Switched List.
func TestPathSwitchRequestMultipleSessions(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000e5", "ps-multi-src")
	targetGNB := createGnBWithID(t, "0000e6", "ps-multi-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000003")
	establishPDUSession(t, sourceGNB, ueID, 2)
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":303,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"},{"id":2,"dl_teid":3,"dl_ip":"10.3.0.3"}]`, amf))

	assertPathSwitchType(t, "multi-session path switch", status, body, ngapPathSwitchRequestAcknowledge)
	assertCarriesPDUSessions(t, body, []int64{1, 2}, "PathSwitchRequestAcknowledge switched list")
}

// TestPathSwitchRequestPartialSuccess — §8.4.4.3: a path switch is acknowledged
// (not failed) as long as at least one PDU session switches; the unswitchable
// session is simply absent from the switched list.
func TestPathSwitchRequestPartialSuccess(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000e7", "ps-part-src")
	targetGNB := createGnBWithID(t, "0000e8", "ps-part-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000004") // holds session 1 only
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":304,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"},{"id":5,"dl_teid":3,"dl_ip":"10.3.0.3"}]`, amf))

	assertPathSwitchType(t, "partial-success path switch", status, body, ngapPathSwitchRequestAcknowledge)
	assertCarriesPDUSessions(t, body, []int64{1}, "PathSwitchRequestAcknowledge switched list (only the held session)")
}

// TestPathSwitchRequestFailedToSetupList — §9.2.3.8: a path switch may carry a
// PDU Session Resource Failed to Setup List for sessions the target could not
// set up; the AMF still acknowledges the sessions that did switch.
func TestPathSwitchRequestFailedToSetupList(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000e9", "ps-fail-src")
	targetGNB := createGnBWithID(t, "0000ea", "ps-fail-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000005")
	establishPDUSession(t, sourceGNB, ueID, 2)
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":305,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}],"failed_pdu_sessions":[2]`, amf))

	assertPathSwitchType(t, "path switch with failed-to-setup list", status, body, ngapPathSwitchRequestAcknowledge)
	assertCarriesPDUSessions(t, body, []int64{1}, "PathSwitchRequestAcknowledge switched list")
}

// TestPathSwitchRequestInvalidPDUSessionIDFails: a path switch naming a PDU
// Session ID outside the valid NAS range (1..15, TS 24.007) cannot switch any
// session, so the AMF must fail it (§8.4.4.3).
func TestPathSwitchRequestInvalidPDUSessionIDFails(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000eb", "ps-badid-src")
	targetGNB := createGnBWithID(t, "0000ec", "ps-badid-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000006")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":306,"pdu_sessions":[{"id":16,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))
	assertPathSwitchType(t, "path switch with out-of-range PDU Session ID 16", status, body, ngapPathSwitchRequestFailure)

	assertUEStillConnected(t, sourceGNB, ueID)
}

// Protocol IE ids relevant to Path Switch Request handling (TS 38.413 §9.3.1.x).
const (
	ieRANUENGAPID                          = 85
	ieSourceAMFUENGAPID                    = 100
	iePDUSessionResourceToBeSwitchedDLList = 76
	ieUESecurityCapabilities               = 119
	ieSecurityContext                      = 93
	ieAllowedNSSAI                         = 0
)

// TestPathSwitchRequestAcknowledgeCarriesMandatoryIEs — §9.2.3.9: a Path Switch
// Request Acknowledge must carry the Security Context (fresh {NH, NCC}) and the
// Allowed NSSAI, both mandatory.
func TestPathSwitchRequestAcknowledgeCarriesMandatoryIEs(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000f0", "ps-ackies-src")
	targetGNB := createGnBWithID(t, "0000f1", "ps-ackies-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000008")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":308,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))

	assertPathSwitchType(t, "acknowledge mandatory IEs", status, body, ngapPathSwitchRequestAcknowledge)

	secCtx := ngapIEByID(body, ieSecurityContext)
	if secCtx == nil {
		t.Errorf("acknowledge is missing the mandatory Security Context IE (TS 38.413 §9.2.3.9)\n  body: %s", body)
	} else if _, ok := secCtx["next_hop_chaining_count"]; !ok {
		t.Errorf("Security Context IE carries no Next Hop Chaining Count (TS 33.501 §6.9.2.3.2)\n  body: %s", body)
	}

	if ngapIEByID(body, ieAllowedNSSAI) == nil {
		t.Errorf("acknowledge is missing the mandatory Allowed NSSAI IE (TS 38.413 §9.2.3.9)\n  body: %s", body)
	}
}

// pathSwitchNCC extracts the Next Hop Chaining Count from a Path Switch Request
// Acknowledge's Security Context IE.
func pathSwitchNCC(t *testing.T, body []byte) int64 {
	t.Helper()

	ie := ngapIEByID(body, ieSecurityContext)
	if ie == nil {
		t.Fatalf("acknowledge missing Security Context IE\n  body: %s", body)
	}

	v, ok := ie["next_hop_chaining_count"].(float64)
	if !ok {
		t.Fatalf("Security Context IE carries no next_hop_chaining_count\n  body: %s", body)
	}

	return int64(v)
}

// TestPathSwitchRequestNCCIncrements — TS 33.501 §6.9.2.3.2: on each PATH SWITCH
// REQUEST the AMF shall increase its locally kept NCC by one and return the
// fresh {NH, NCC} in the acknowledge. Two consecutive switches for the same UE
// must therefore yield NCC values differing by exactly one (mod 8).
func TestPathSwitchRequestNCCIncrements(t *testing.T) {
	gnbA := createGnBWithID(t, "000126", "ps-ncc-a")
	gnbB := createGnBWithID(t, "000127", "ps-ncc-b")
	gnbC := createGnBWithID(t, "000128", "ps-ncc-c")

	ueID := establishRegisteredUEWithSUPI(t, gnbA, "imsi-001010000000023")
	amf, _ := ueNGAPIDs(t, gnbA, ueID)

	status, body := sendPathSwitch(t, gnbB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":220,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))
	assertPathSwitchType(t, "first path switch", status, body, ngapPathSwitchRequestAcknowledge)
	ncc1 := pathSwitchNCC(t, body)

	status, body = sendPathSwitch(t, gnbC,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":221,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))
	assertPathSwitchType(t, "second path switch", status, body, ngapPathSwitchRequestAcknowledge)
	ncc2 := pathSwitchNCC(t, body)

	if ncc2 != (ncc1+1)%8 {
		t.Errorf("NCC did not advance by one across path switches: first=%d second=%d, want second=%d (TS 33.501 §6.9.2.3.2)\n  body: %s",
			ncc1, ncc2, (ncc1+1)%8, body)
	}
}

// TestPathSwitchRequestMissingMandatoryIE — §10.3.5: a Path Switch Request
// missing a mandatory reject-criticality IE leaves the AMF unable to build a
// Path Switch Request Failure (which itself needs those IEs), so it must
// terminate the procedure with an Error Indication. A missing ignore-criticality
// IE must be ignored and the procedure must continue.
func TestPathSwitchRequestMissingMandatoryIE(t *testing.T) {
	cases := []struct {
		name   string
		omitIE int
		want   string
	}{
		{"RANUENGAPID (reject)", ieRANUENGAPID, ngapErrorIndication},
		{"SourceAMFUENGAPID (reject)", ieSourceAMFUENGAPID, ngapErrorIndication},
		{"PDUSessionToBeSwitchedList (reject)", iePDUSessionResourceToBeSwitchedDLList, ngapErrorIndication},
		{"UESecurityCapabilities (ignore)", ieUESecurityCapabilities, ngapPathSwitchRequestAcknowledge},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sourceGNB := createGnBWithID(t, fmt.Sprintf("0000%02x", 0xf2+i*2), "ps-omit-src")
			targetGNB := createGnBWithID(t, fmt.Sprintf("0000%02x", 0xf3+i*2), "ps-omit-tgt")

			ueID := establishRegisteredUEWithSUPI(t, sourceGNB, fmt.Sprintf("imsi-00101000000001%d", i))
			amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

			status, body := sendPathSwitch(t, targetGNB,
				fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}],"omit_ies":[%d]`, amf, 320+i, tc.omitIE))
			assertPathSwitchType(t, "path switch omitting IE "+tc.name, status, body, tc.want)
		})
	}
}

// TestPathSwitchRequestMalformedTransferFails: a Path Switch Request Transfer
// whose bytes are not a valid §9.3.4.8 transfer cannot be applied, so the
// session does not switch and the AMF fails the procedure (§8.4.4.3).
func TestPathSwitchRequestMalformedTransferFails(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000ed", "ps-badxfer-src")
	targetGNB := createGnBWithID(t, "0000ee", "ps-badxfer-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000007")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":307,"pdu_sessions":[{"id":1,"raw_transfer":"deadbeef"}]`, amf))
	assertPathSwitchType(t, "path switch with malformed transfer", status, body, ngapPathSwitchRequestFailure)

	assertUEStillConnected(t, sourceGNB, ueID)
}
