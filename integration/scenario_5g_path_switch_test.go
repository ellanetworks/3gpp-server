// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

func sendPathSwitch(t *testing.T, gnbID, fields string) (int, []byte) {
	t.Helper()

	body := `{"message_type":"path_switch_request",` + fields +
		`,"wait_for":["PathSwitchRequestAcknowledge","PathSwitchRequestFailure","ErrorIndication"],"timeout_ms":5000}`

	return doRequest(t, "POST", "/gnb/"+gnbID+"/ngap", body)
}

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

func ngapReleasedPDUSessionIDs(body []byte) []int64 {
	var top struct {
		NGAP struct {
			ReleasePDUSessionIDs []int64 `json:"release_pdu_session_ids"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	return top.NGAP.ReleasePDUSessionIDs
}

func Test5GPathSwitchRequestUnknownUEFails(t *testing.T) {
	gnb := createGNBWithID(t, "0000e0", "ps-unknown")

	status, body := sendPathSwitch(t, gnb,
		`"amf_ue_ngap_id":987654,"ran_ue_ngap_id":300,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`)
	assertPathSwitchType(t, "path switch for unknown AMF UE NGAP ID", status, body, ngapPathSwitchRequestFailure)
}

func Test5GPathSwitchRequestNoSwitchableSessionFails(t *testing.T) {
	sourceGNB := createGNBWithID(t, "0000e1", "ps-none-src")
	targetGNB := createGNBWithID(t, "0000e2", "ps-none-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000001")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":301,"pdu_sessions":[{"id":5,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))
	assertPathSwitchType(t, "path switch naming a non-held PDU session", status, body, ngapPathSwitchRequestFailure)

	assertUEStillConnected(t, sourceGNB, ueID)
}

func Test5GPathSwitchRequestFailureReportsReleasedSessions(t *testing.T) {
	sourceGNB := createGNBWithID(t, "0000e3", "ps-rel-src")
	targetGNB := createGNBWithID(t, "0000e4", "ps-rel-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000002")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":302,"pdu_sessions":[{"id":5,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))

	assertPathSwitchType(t, "all-fail path switch", status, body, ngapPathSwitchRequestFailure)

	if released := ngapReleasedPDUSessionIDs(body); len(released) == 0 {
		t.Errorf("Path Switch Request Failure carries no PDU Session Resource Released List; it must name the "+
			"session(s) that failed to switch so the NG-RAN node can release them (TS 38.413 §9.2.3.10, §8.4.4.3)\n  body: %s", body)
	}
}

func Test5GPathSwitchRequestMultipleSessions(t *testing.T) {
	sourceGNB := createGNBWithID(t, "0000e5", "ps-multi-src")
	targetGNB := createGNBWithID(t, "0000e6", "ps-multi-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000003")
	establishPDUSession(t, sourceGNB, ueID, 2)
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":303,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"},{"id":2,"dl_teid":3,"dl_ip":"10.3.0.3"}]`, amf))

	assertPathSwitchType(t, "multi-session path switch", status, body, ngapPathSwitchRequestAcknowledge)
	assertCarriesPDUSessions(t, body, []int64{1, 2}, "PathSwitchRequestAcknowledge switched list")
}

// One switchable session is enough for an acknowledge (TS 38.413 §8.4.4.3).
func Test5GPathSwitchRequestPartialSuccess(t *testing.T) {
	sourceGNB := createGNBWithID(t, "0000e7", "ps-part-src")
	targetGNB := createGNBWithID(t, "0000e8", "ps-part-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000004")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":304,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"},{"id":5,"dl_teid":3,"dl_ip":"10.3.0.3"}]`, amf))

	assertPathSwitchType(t, "partial-success path switch", status, body, ngapPathSwitchRequestAcknowledge)
	assertCarriesPDUSessions(t, body, []int64{1}, "PathSwitchRequestAcknowledge switched list (only the held session)")
}

func Test5GPathSwitchRequestFailedToSetupList(t *testing.T) {
	sourceGNB := createGNBWithID(t, "0000e9", "ps-fail-src")
	targetGNB := createGNBWithID(t, "0000ea", "ps-fail-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000005")
	establishPDUSession(t, sourceGNB, ueID, 2)
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":305,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}],"failed_pdu_sessions":[2]`, amf))

	assertPathSwitchType(t, "path switch with failed-to-setup list", status, body, ngapPathSwitchRequestAcknowledge)
	assertCarriesPDUSessions(t, body, []int64{1}, "PathSwitchRequestAcknowledge switched list")
}

// PDU Session ID 16 is outside the valid 1..15 range (TS 24.007 §11.2.3.1b).
func Test5GPathSwitchRequestInvalidPDUSessionIDFails(t *testing.T) {
	sourceGNB := createGNBWithID(t, "0000eb", "ps-badid-src")
	targetGNB := createGNBWithID(t, "0000ec", "ps-badid-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000006")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":306,"pdu_sessions":[{"id":16,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))
	assertPathSwitchType(t, "path switch with out-of-range PDU Session ID 16", status, body, ngapPathSwitchRequestFailure)

	assertUEStillConnected(t, sourceGNB, ueID)
}

// TS 38.413 §9.4.7.
const (
	ieRANUENGAPID                          = 85
	ieSourceAMFUENGAPID                    = 100
	iePDUSessionResourceToBeSwitchedDLList = 76
	ieUESecurityCapabilities               = 119
)

func Test5GPathSwitchRequestAcknowledgeCarriesMandatoryIEs(t *testing.T) {
	sourceGNB := createGNBWithID(t, "0000f0", "ps-ackies-src")
	targetGNB := createGNBWithID(t, "0000f1", "ps-ackies-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000008")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":308,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}]`, amf))

	assertPathSwitchType(t, "acknowledge mandatory IEs", status, body, ngapPathSwitchRequestAcknowledge)

	if jsonGet(body, "ngap.security_context.next_hop_chaining_count") == "" {
		t.Errorf("acknowledge is missing the mandatory Security Context IE and its Next Hop Chaining Count (TS 38.413 §9.2.3.9, TS 33.501 §6.9.2.3.2)\n  body: %s", body)
	}

	if ngapField(body, "allowed_nssai") == nil {
		t.Errorf("acknowledge is missing the mandatory Allowed NSSAI IE (TS 38.413 §9.2.3.9)\n  body: %s", body)
	}
}

func pathSwitchNCC(t *testing.T, body []byte) int64 {
	t.Helper()

	var top struct {
		NGAP struct {
			SecurityContext *struct {
				NCC int64 `json:"next_hop_chaining_count"`
			} `json:"security_context"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil || top.NGAP.SecurityContext == nil {
		t.Fatalf("acknowledge missing Security Context Next Hop Chaining Count\n  body: %s", body)
	}

	return top.NGAP.SecurityContext.NCC
}

func Test5GPathSwitchRequestNCCIncrements(t *testing.T) {
	gnbA := createGNBWithID(t, "000126", "ps-ncc-a")
	gnbB := createGNBWithID(t, "000127", "ps-ncc-b")
	gnbC := createGNBWithID(t, "000128", "ps-ncc-c")

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

// A missing reject-criticality IE leaves the AMF unable to build the Path Switch
// Request Failure itself, so TS 38.413 §10.3.5 requires an Error Indication.
func Test5GPathSwitchRequestMissingMandatoryIE(t *testing.T) {
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
			sourceGNB := createGNBWithID(t, fmt.Sprintf("0000%02x", 0xf2+i*2), "ps-omit-src")
			targetGNB := createGNBWithID(t, fmt.Sprintf("0000%02x", 0xf3+i*2), "ps-omit-tgt")

			ueID := establishRegisteredUEWithSUPI(t, sourceGNB, fmt.Sprintf("imsi-00101000000001%d", i))
			amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

			status, body := sendPathSwitch(t, targetGNB,
				fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":2,"dl_ip":"10.3.0.3"}],"omit_ies":[%d]`, amf, 320+i, tc.omitIE))
			assertPathSwitchType(t, "path switch omitting IE "+tc.name, status, body, tc.want)
		})
	}
}

func Test5GPathSwitchRequestMalformedTransferFails(t *testing.T) {
	sourceGNB := createGNBWithID(t, "0000ed", "ps-badxfer-src")
	targetGNB := createGNBWithID(t, "0000ee", "ps-badxfer-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000007")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	status, body := sendPathSwitch(t, targetGNB,
		fmt.Sprintf(`"amf_ue_ngap_id":%d,"ran_ue_ngap_id":307,"pdu_sessions":[{"id":1,"raw_transfer":"deadbeef"}]`, amf))
	assertPathSwitchType(t, "path switch with malformed transfer", status, body, ngapPathSwitchRequestFailure)

	assertUEStillConnected(t, sourceGNB, ueID)
}
