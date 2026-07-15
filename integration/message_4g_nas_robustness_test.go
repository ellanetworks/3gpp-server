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
// call from a goroutine.
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

// Test4GConcurrentAttach checks the MME keeps concurrent UEs' contexts, security
// contexts, and GUTIs separate, registering them all.
func Test4GConcurrentAttach(t *testing.T) {
	enbID := mustCreateENB(t)

	const n = 8

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
			t.Errorf("concurrent attach failed: %v", err)
		}
	}
}

// Test4GMalformedNAS checks the MME never mistakes a garbage NAS PDU carried in
// an Initial UE Message for a valid attach.
func Test4GMalformedNAS(t *testing.T) {
	enbID := mustCreateENB(t)

	garbage := []string{
		"00",
		"ff",
		"deadbeef",
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

// Test4GBadMACSecurityModeComplete checks the MME discards a Security Mode
// Complete whose NAS-MAC does not verify (TS 24.301 §4.4.4).
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
