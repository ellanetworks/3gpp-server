// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

const networkDeregIMSI = "001010000000112"

// Test5GNetworkInitiatedDeregistration is the 5G twin of
// Test4GNetworkInitiatedDetach: deleting a registered subscriber must make the
// AMF deregister the UE with a DEREGISTRATION REQUEST (TS 24.501 §5.5.2.3).
func Test5GNetworkInitiatedDeregistration(t *testing.T) {
	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("ella core token: %v", err)
	}

	if err := createSubscriber(token, networkDeregIMSI); err != nil {
		t.Fatalf("create subscriber: %v", err)
	}
	t.Cleanup(func() {
		if err := createSubscriber(token, networkDeregIMSI); err != nil {
			t.Errorf("restore subscriber %s: %v", networkDeregIMSI, err)
		}
	})

	gnbID := mustCreateGNB(t)

	ueBody := fmt.Sprintf(`{
		"supi": "imsi-%s",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": "internet",
		"routing_indicator": "0", "protection_scheme": "0", "public_key_id": "0"
	}`, networkDeregIMSI)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue", ueBody)
	if status != 201 {
		t.Fatalf("create UE: HTTP %d: %s", status, resp)
	}
	ueID := jsonGet(resp, "ue_id")

	doRegistrationFlow(t, gnbID, ueID)

	deleteSubscriber(t, token, networkDeregIMSI)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":8000}`)
	if status != 200 {
		t.Fatalf("no Downlink NAS Transport after subscriber deletion (HTTP %d) — the AMF must deregister the UE (TS 24.501 §5.5.2.3)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != "deregistration_request_ue_terminated" {
		t.Fatalf("AMF-initiated NAS = %q, want deregistration_request_ue_terminated (TS 24.501 §5.5.2.3)\n  body: %s", got, body)
	}
}
