// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// createENBID creates an eNB with a specific eNB ID, asserts S1 Setup succeeds,
// and returns the store handle (registers cleanup).
func createENBID(t *testing.T, enbID int) string {
	t.Helper()

	body := fmt.Sprintf(`{"mme_address":"10.3.0.2:36412","enb_s1_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"0001","enb_id":%d,"name":"flood-enb"}`, enbID)

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create eNB %d: HTTP %d: %s", enbID, status, resp)
	}

	id := jsonGet(resp, "enb_id")
	t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })

	if got := jsonGet(resp, "response.message_type"); got != "S1SetupResponse" {
		t.Fatalf("eNB %d: response = %q, want S1SetupResponse; body: %s", enbID, got, resp)
	}

	return id
}

// TestEPSAssociationFlood opens many eNB S1-MME associations at once and checks
// the MME completes S1 Setup for all of them and remains responsive to one more.
func TestEPSAssociationFlood(t *testing.T) {
	const n = 50

	for i := 1; i <= n; i++ {
		createENBID(t, i)
	}

	// The MME is still serving new associations.
	createENBID(t, n+1)
}

// TestEPSAttachFlood attaches many distinct subscribers concurrently on one eNB
// and checks they all register and that the MME stays responsive to a fresh UE.
func TestEPSAttachFlood(t *testing.T) {
	enbID := mustCreateENB(t)

	const n = 25

	errs := make(chan error, n)

	var wg sync.WaitGroup

	for i := 1; i <= n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			errs <- attachUEConcurrent(enbID, testSUPI(i)[len("imsi-"):])
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("flood attach failed: %v", err)
		}
	}

	fresh := createENBUEWithIMSI(t, enbID, testSUPI(n + 1)[len("imsi-"):])
	fullAttach(t, enbID, fresh)
}

// TestEPSOversizedPDU sends oversized S1AP and NAS PDUs (near the SCTP read
// buffer) and checks the MME does not crash — a clean attach still completes.
func TestEPSOversizedPDU(t *testing.T) {
	// ~60 KB of bytes as a raw S1AP PDU.
	if status, resp := createENBRaw(t, strings.Repeat("ab", 60000)); status != 201 {
		t.Fatalf("oversized S1AP: server failed to handle it (HTTP %d): %s", status, resp)
	}

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	// ~8 KB NAS: a large garbage NAS PDU within the S1AP OCTET STRING encoder's
	// 16 K bound (NAS messages are never this big in practice).
	body := fmt.Sprintf(`{"message_type":"attach_request","raw_nas_pdu":%q,"timeout_ms":800}`, strings.Repeat("cd", 8000))
	if status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/nas", body); status != 200 {
		t.Fatalf("oversized NAS: server failed to handle it (HTTP %d): %s", status, resp)
	}

	// The MME stayed on its feet: a fresh clean attach completes.
	fresh := createENBUEWithIMSI(t, enbID, testSUPI(30)[len("imsi-"):])
	fullAttach(t, enbID, fresh)
}
