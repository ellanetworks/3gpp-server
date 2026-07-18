// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"strings"
	"testing"
)

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

func Test5GAssociationFlood(t *testing.T) {
	const n = 50

	for i := 0; i < n; i++ {
		createGnBAssertingNGSetup(t, "flood-gnb")
	}

	createGnBAssertingNGSetup(t, "flood-probe")
}

func Test5GOversizedPDU(t *testing.T) {
	gnbID := mustCreateGnB(t)

	// ab: the NGAP-PDU CHOICE extension bit is set, so the Type of Message IE
	// does not decode (TS 38.413 §9.3.1.1).
	const oversizedClause = "§10.2, §10.3.4.1A"

	resp := sendRawNGAPAwaitingErrorIndication(t, gnbID, strings.Repeat("ab", 60000), oversizedClause)
	assertErrorIndicationReported(t, resp, oversizedClause)

	ueID := mustCreateUE(t, gnbID)

	// 8 KB stays within the NGAP OCTET STRING encoder's bound, so the PDU reaches the AMF.
	body := fmt.Sprintf(`{"message_type":"registration_request","raw_nas_pdu":%q,"timeout_ms":800}`, strings.Repeat("cd", 8000))
	if status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body); status != 200 {
		t.Fatalf("oversized NAS: server failed to handle it (HTTP %d): %s", status, resp)
	}

	fresh := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, fresh)
}
