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

func createENBID(t *testing.T, enbID int) string {
	t.Helper()

	body := fmt.Sprintf(`{"mme_address":"10.3.0.2:36412","enb_s1_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"0001","enb_id":"%x","name":"flood-enb"}`, enbID)

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create eNB %d: HTTP %d: %s", enbID, status, resp)
	}

	id := jsonGet(resp, "enb_id")
	t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })

	if got := jsonGet(resp, "s1_setup_response.message_type"); got != "S1SetupResponse" {
		t.Fatalf("eNB %d: response = %q, want S1SetupResponse; body: %s", enbID, got, resp)
	}

	return id
}

func Test4GAssociationFlood(t *testing.T) {
	const n = 50

	for i := 1; i <= n; i++ {
		createENBID(t, claimENBID())
	}

	createENBID(t, claimENBID())
}

func Test4GAttachFlood(t *testing.T) {
	enbID := mustCreateENB(t)

	const n = 25

	supis := claimSubscribers(t, n)

	errs := make(chan error, n)

	var wg sync.WaitGroup

	for _, supi := range supis {
		wg.Add(1)

		go func(supi string) {
			defer wg.Done()

			errs <- attachUEConcurrent(enbID, supi[len("imsi-"):])
		}(supi)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("flood attach failed: %v", err)
		}
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

func Test4GOversizedPDU(t *testing.T) {
	if status, resp := createENBRaw(t, strings.Repeat("ab", 60000)); status != 201 {
		t.Fatalf("oversized S1AP: server failed to handle it (HTTP %d): %s", status, resp)
	}

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	// ~8 KB stays within the S1AP OCTET STRING encoder's 16 K bound.
	body := fmt.Sprintf(`{"message_type":"attach_request","raw_nas_pdu":%q,"timeout_ms":800}`, strings.Repeat("cd", 8000))
	if status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", body); status != 200 {
		t.Fatalf("oversized NAS: server failed to handle it (HTTP %d): %s", status, resp)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
