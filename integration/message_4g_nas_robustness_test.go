// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"sync"
	"testing"
)

// attachUEConcurrent runs a full attach without a *testing.T, so it is safe to
// call from a goroutine. It returns an error on the first non-compliant step.
func attachUEConcurrent(enbID, imsi string) error {
	createBody := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000000"}`, imsi, testK, testOPc)

	status, body, err := post("/enb/"+enbID+"/ue", createBody)
	if err != nil {
		return err
	}

	if status != 201 {
		return fmt.Errorf("create ue: HTTP %d: %s", status, body)
	}

	ueID := jsonGet(body, "ue_id")

	steps := []struct{ msg, wantNAS string }{
		{"attach_request", "authentication_request"},
		{"authentication_response", "security_mode_command"},
		{"security_mode_complete", "attach_accept"},
		{"attach_complete", ""},
	}

	for _, s := range steps {
		status, body, err := post("/enb/"+enbID+"/ue/"+ueID+"/nas", fmt.Sprintf(`{"message_type":%q}`, s.msg))
		if err != nil {
			return err
		}

		if status != 200 {
			return fmt.Errorf("%s: HTTP %d: %s", s.msg, status, body)
		}

		if s.wantNAS != "" {
			if got := jsonGet(body, "nas.message_type"); got != s.wantNAS {
				return fmt.Errorf("%s: nas.message_type = %q, want %q", s.msg, got, s.wantNAS)
			}
		}
	}

	return nil
}

// TestEPSConcurrentAttach attaches several distinct subscribers at once on one
// eNB, checking the MME keeps their UE contexts, security contexts, and GUTIs
// separate and registers them all.
func Test4GConcurrentAttach(t *testing.T) {
	enbID := mustCreateENB(t)

	const n = 8

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
			t.Errorf("concurrent attach failed: %v", err)
		}
	}
}

// TestEPSMalformedNAS throws garbage NAS PDUs at the MME inside an Initial UE
// Message and verifies it never mistakes one for a valid attach, then confirms a
// clean attach still completes — proof the MME stayed on its feet.
func Test4GMalformedNAS(t *testing.T) {
	enbID := mustCreateENB(t)

	garbage := []string{
		"00",         // single byte
		"ff",         // single byte
		"deadbeef",   // not NAS
		"0741",       // EMM Attach Request header, then nothing
		"0741ffffff", // EMM Attach Request header, then garbage
	}

	for _, g := range garbage {
		t.Run("garbage "+g, func(t *testing.T) {
			ueID := mustCreateENBUE(t, enbID)

			body := fmt.Sprintf(`{"message_type":"attach_request","raw_nas_pdu":%q,"timeout_ms":800}`, g)

			status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/nas", body)
			if status != 200 {
				t.Fatalf("server failed to handle raw NAS (HTTP %d): %s", status, resp)
			}

			if got := jsonGet(resp, "nas.message_type"); got == "attach_accept" {
				t.Fatalf("MME accepted malformed NAS as an attach; body: %s", resp)
			}
		})
	}

	t.Run("clean attach still completes", func(t *testing.T) {
		if got := jsonGet(attachToAccept(t, enbID), "nas.message_type"); got != "attach_accept" {
			t.Fatalf("MME unhealthy after malformed-NAS barrage: got %q", got)
		}
	})
}

// TestEPSBadMACSecurityModeComplete sends a Security Mode Complete with a
// corrupted NAS-MAC and checks the MME discards it (TS 24.301 §4.4.4) rather than
// completing the attach, then confirms the MME remains healthy.
func Test4GBadMACSecurityModeComplete(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	nasStep(t, enbID, ueID, "attach_request")
	nasStep(t, enbID, ueID, "authentication_response")

	resp := nasBody(t, enbID, ueID,
		`{"message_type":"security_mode_complete","corrupt_mac":true,"timeout_ms":1500}`)

	if got := jsonGet(resp, "s1ap.message_type"); got == "InitialContextSetupRequest" {
		t.Fatalf("MME accepted a Security Mode Complete with an invalid NAS-MAC (TS 24.301 §4.4.4); body: %s", resp)
	}

	if got := jsonGet(attachToAccept(t, enbID), "nas.message_type"); got != "attach_accept" {
		t.Fatalf("MME unhealthy after bad-MAC Security Mode Complete: got %q", got)
	}
}
