// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

func pathSwitchRequest(t *testing.T, gnbID, body string) []byte {
	t.Helper()

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap", body)
	if status != 200 {
		t.Fatalf("path_switch_request: HTTP %d\n  body: %s", status, resp)
	}

	return resp
}

func ngapIEByID(body []byte, id int64) map[string]any {
	var top struct {
		NGAP struct {
			IEs []map[string]any `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	for _, ie := range top.NGAP.IEs {
		if v, ok := ie["id"].(float64); ok && int64(v) == id {
			return ie
		}
	}

	return nil
}

// TS 38.413 §9.3.1.86.
const ngapProtocolIEIDUESecurityCapabilities = 119

func Test5GPathSwitchRequestSuccess(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000c0", "ps-src")
	targetGNB := createGnBWithID(t, "0000c1", "ps-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000001")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	const newRanID = 200

	resp := pathSwitchRequest(t, targetGNB, fmt.Sprintf(`{
		"message_type": "path_switch_request",
		"amf_ue_ngap_id": %d,
		"ran_ue_ngap_id": %d,
		"pdu_sessions": [{"id": 1, "dl_teid": 2, "dl_ip": "10.3.0.3"}],
		"wait_for": ["PathSwitchRequestAcknowledge", "PathSwitchRequestFailure", "ErrorIndication"],
		"timeout_ms": 5000
	}`, amf, newRanID))

	if got := jsonGet(resp, "ngap.message_type"); got != ngapPathSwitchRequestAcknowledge {
		t.Fatalf("path switch for an existing UE context: message_type = %q, want PathSwitchRequestAcknowledge (TS 38.413 §8.4.4.2)\n  body: %s", got, resp)
	}

	if gotAmf, ok := ngapFirstAmfUeNgapID(resp); !ok || gotAmf != amf {
		t.Errorf("acknowledge AMF UE NGAP ID = %d (present=%v), want %d (TS 38.413 §8.4.4.2)\n  body: %s", gotAmf, ok, amf, resp)
	}

	if got := jsonGet(resp, "ngap.ies"); got == "" {
		t.Errorf("acknowledge carries no IEs\n  body: %s", resp)
	}
}

func Test5GPathSwitchRequestDuplicatePDUSessionIDsFailure(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000c2", "ps-dup-src")
	targetGNB := createGnBWithID(t, "0000c3", "ps-dup-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000002")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	resp := pathSwitchRequest(t, targetGNB, fmt.Sprintf(`{
		"message_type": "path_switch_request",
		"amf_ue_ngap_id": %d,
		"ran_ue_ngap_id": 201,
		"pdu_sessions": [
			{"id": 1, "dl_teid": 2, "dl_ip": "10.3.0.3"},
			{"id": 1, "dl_teid": 3, "dl_ip": "10.3.0.3"}
		],
		"wait_for": ["PathSwitchRequestFailure", "PathSwitchRequestAcknowledge", "ErrorIndication"],
		"timeout_ms": 5000
	}`, amf))

	if got := jsonGet(resp, "ngap.message_type"); got != ngapPathSwitchRequestFailure {
		t.Errorf("path switch with duplicate PDU Session IDs: message_type = %q, want PathSwitchRequestFailure (TS 38.413 §8.4.4.4)\n  body: %s", got, resp)
	}

	assertUEStillConnected(t, sourceGNB, ueID)
}

func Test5GPathSwitchRequestSecurityCapabilityMismatchAcknowledged(t *testing.T) {
	sourceGNB := createGnBWithID(t, "0000c4", "ps-sec-src")
	targetGNB := createGnBWithID(t, "0000c5", "ps-sec-tgt")

	ueID := establishRegisteredUEWithSUPI(t, sourceGNB, "imsi-001010000000003")
	amf, _ := ueNGAPIDs(t, sourceGNB, ueID)

	// All-zero algorithms cannot match what the UE presented at registration.
	resp := pathSwitchRequest(t, targetGNB, fmt.Sprintf(`{
		"message_type": "path_switch_request",
		"amf_ue_ngap_id": %d,
		"ran_ue_ngap_id": 202,
		"ue_security_capabilities": {"nr_encryption": "0000", "nr_integrity": "0000"},
		"pdu_sessions": [{"id": 1, "dl_teid": 2, "dl_ip": "10.3.0.3"}],
		"wait_for": ["PathSwitchRequestAcknowledge", "PathSwitchRequestFailure", "ErrorIndication"],
		"timeout_ms": 5000
	}`, amf))

	if got := jsonGet(resp, "ngap.message_type"); got != ngapPathSwitchRequestAcknowledge {
		t.Fatalf("path switch with mismatched UE security capabilities: message_type = %q, want PathSwitchRequestAcknowledge (the AMF must not reject; TS 33.501 §6.7.3.1)\n  body: %s", got, resp)
	}

	ie := ngapIEByID(resp, ngapProtocolIEIDUESecurityCapabilities)
	if ie == nil {
		t.Fatalf("acknowledge omits the UE Security Capabilities IE; on a mismatch the AMF must return its locally stored capabilities (TS 33.501 §6.7.3.1)\n  body: %s", resp)
	}

	caps, _ := ie["ue_security_capabilities"].(map[string]any)
	if caps == nil {
		t.Fatalf("UE Security Capabilities IE carries no decoded value\n  body: %s", resp)
	}

	// A UE always supports a non-null integrity algorithm (TS 33.501 §5.11.2), so
	// the AMF's stored NR integrity capabilities are non-zero.
	if nrInt, _ := caps["nr_integrity"].(string); nrInt == "" || nrInt == "0000" {
		t.Errorf("returned NR integrity capabilities = %q, want the AMF's stored non-zero value (TS 33.501 §6.7.3.1)\n  body: %s", nrInt, resp)
	}
}
