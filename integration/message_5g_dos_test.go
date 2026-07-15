// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"strings"
	"testing"
)

// createGnBAssertingNGSetup creates a gNB on an allocated gNB ID, asserts the
// AMF answered with an NG Setup Response (TS 38.413 §8.7.1), and returns its
// store ID.
func createGnBAssertingNGSetup(t *testing.T, name string) string {
	t.Helper()

	gnbID := claimGnBID()

	body := fmt.Sprintf(`{
		"amf_address": "10.3.0.2:38412", "gnb_n2_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "000001",
		"gnb_id": %q, "name": %q, "sst": 1
	}`, gnbID, name)

	status, resp := doRequest(t, "POST", "/gnb", body)
	if status != 201 {
		t.Fatalf("create gnb %s: HTTP %d: %s", gnbID, status, resp)
	}

	id := jsonGet(resp, "gnb_id")
	t.Cleanup(func() { doRequest(t, "DELETE", "/gnb/"+id, "") })

	if got := jsonGet(resp, "ng_setup_response.message_type"); got != ngapNGSetupResponse {
		t.Fatalf("gnb %s: ng_setup_response.message_type = %q, want NGSetupResponse (TS 38.413 §8.7.1); body: %s", gnbID, got, resp)
	}

	return id
}

// Test5GAssociationFlood opens many gNB N2 associations at once and checks the
// AMF completes NG Setup for all of them and remains responsive to one more.
func Test5GAssociationFlood(t *testing.T) {
	const n = 50

	for i := 0; i < n; i++ {
		createGnBAssertingNGSetup(t, "flood-gnb")
	}

	// The AMF is still serving new associations.
	createGnBAssertingNGSetup(t, "flood-probe")
}

// Test5GOversizedPDU sends oversized NGAP and NAS PDUs (near the SCTP read
// buffer) and checks the AMF does not crash — a clean registration still
// completes.
func Test5GOversizedPDU(t *testing.T) {
	gnbID := mustCreateGnB(t)

	// ~60 KB of bytes as a raw NGAP PDU on an established N2 association.
	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap",
		fmt.Sprintf(`{"raw_ngap_pdu":%q}`, strings.Repeat("ab", 60000)))
	if status != 200 {
		t.Fatalf("oversized NGAP: server failed to handle it (HTTP %d): %s", status, resp)
	}

	ueID := mustCreateUE(t, gnbID)

	// ~8 KB NAS: a large garbage NAS PDU within the NGAP OCTET STRING encoder's
	// bound (NAS messages are never this big in practice).
	body := fmt.Sprintf(`{"message_type":"registration_request","raw_nas_pdu":%q,"timeout_ms":800}`, strings.Repeat("cd", 8000))
	if status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body); status != 200 {
		t.Fatalf("oversized NAS: server failed to handle it (HTTP %d): %s", status, resp)
	}

	// The AMF stayed on its feet: a fresh clean registration completes.
	fresh := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, fresh)
}
