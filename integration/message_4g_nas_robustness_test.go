// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"sync"
	"testing"
)

// Errors are returned, not fatalled: this runs on goroutines, where t.Fatal is illegal.
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
		status, body, err := post("/enb/"+enbID+"/ue/"+ueID+"/s1ap", fmt.Sprintf(`{"message_type":%q}`, s.msg))
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

// TS 24.301 §5.5.1.2.7 b) binds only a PDU whose EMM header identifies an ATTACH REQUEST.
var malformedNAS = []struct {
	pdu                 string
	attachProtocolError bool
}{
	{pdu: "00"},
	{pdu: "ff"},
	{pdu: "deadbeef"},
	{pdu: "0741", attachProtocolError: true},
	{pdu: "0741ffffff", attachProtocolError: true},
}

func attachRejectCauseAllowed(c string) bool {
	switch c {
	case "96", "99", "100", "111":
		return true
	}

	return false
}

func Test4GMalformedNAS(t *testing.T) {
	enbID := mustCreateENB(t)

	for _, g := range malformedNAS {
		t.Run("garbage "+g.pdu, func(t *testing.T) {
			ueID := mustCreateENBUE(t, enbID)

			timeout := 800
			if g.attachProtocolError {
				timeout = 3000
			}

			body := fmt.Sprintf(`{"message_type":"attach_request","raw_nas_pdu":%q,"timeout_ms":%d}`, g.pdu, timeout)

			status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", body)
			if status != 200 {
				t.Fatalf("server failed to handle raw NAS (HTTP %d): %s", status, resp)
			}

			got := jsonGet(resp, "nas.message_type")
			if got == "attach_accept" {
				t.Fatalf("MME accepted malformed NAS as an attach; body: %s", resp)
			}

			if !g.attachProtocolError {
				return
			}

			if got != "attach_reject" {
				t.Fatalf("nas.message_type = %q, want attach_reject (TS 24.301 §5.5.1.2.7 b)); body: %s", got, resp)
			}

			if c := jsonGet(resp, "nas.emm_cause"); !attachRejectCauseAllowed(c) {
				t.Errorf("attach_reject emm_cause = %q, want 96, 99, 100 or 111 (TS 24.301 §5.5.1.2.7 b)); body: %s", c, resp)
			}
		})
	}

	t.Run("clean attach still completes", func(t *testing.T) {
		if got := jsonGet(attachToAccept(t, enbID), "nas.message_type"); got != "attach_accept" {
			t.Fatalf("MME unhealthy after malformed-NAS barrage: got %q", got)
		}
	})
}

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
