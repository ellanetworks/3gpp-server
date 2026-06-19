// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"strconv"
	"testing"
)

// attachToAccept drives a fresh UE through the full attach and returns the Attach
// Accept response body (which carries the assigned GUTI).
func attachToAccept(t *testing.T, enbID string) []byte {
	t.Helper()

	ueID := mustCreateENBUE(t, enbID)
	nasStep(t, enbID, ueID, "attach_request")
	nasStep(t, enbID, ueID, "authentication_response")

	return nasStep(t, enbID, ueID, "security_mode_complete")
}

// TestGUTIReallocation checks the MME assigns a fresh GUTI on each attach
// (TS 24.301 §5.5.1.2.4) and that the M-TMSIs are not sequentially allocated, as
// required for subscriber-identity confidentiality (TS 23.003 §2.8).
func TestGUTIReallocation(t *testing.T) {
	enbID := mustCreateENB(t)

	const n = 4

	var (
		seen     = map[string]bool{}
		min, max uint64
	)

	for i := 0; i < n; i++ {
		resp := attachToAccept(t, enbID)

		mtmsi := jsonGet(resp, "nas.guti.m_tmsi")
		if mtmsi == "" {
			t.Fatalf("attach %d: Attach Accept missing GUTI; body: %s", i, resp)
		}

		if seen[mtmsi] {
			t.Fatalf("attach %d: M-TMSI %s reused; the MME must reallocate the GUTI", i, mtmsi)
		}

		seen[mtmsi] = true

		v, err := strconv.ParseUint(mtmsi, 16, 32)
		if err != nil {
			t.Fatalf("M-TMSI %q not hex: %v", mtmsi, err)
		}

		if i == 0 || v < min {
			min = v
		}

		if i == 0 || v > max {
			max = v
		}
	}

	// Sequential allocation would pack n M-TMSIs into a span of n-1; a spread far
	// larger than that is evidence of the unpredictable allocation the spec wants.
	if max-min < 1000 {
		t.Fatalf("M-TMSIs span only %d across %d attaches; allocation looks sequential/predictable (TS 23.003 §2.8)", max-min, n)
	}
}

// TestForeignGUTIIdentityRequest checks that an attach using a GUTI the MME does
// not recognise triggers the Identity procedure: the MME requests the IMSI
// (TS 24.301 §5.4.4), and once given it proceeds to authentication.
func TestForeignGUTIIdentityRequest(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"attach_request","foreign_guti":true}`)

	if got := jsonGet(resp, "nas.message_type"); got != "identity_request" {
		t.Fatalf("foreign-GUTI attach: nas.message_type = %q, want identity_request (TS 24.301 §5.4.4); body: %s", got, resp)
	}

	if got := jsonGet(resp, "nas.identity_type"); got != "1" {
		t.Fatalf("identity_type = %q, want 1 (IMSI); body: %s", got, resp)
	}

	auth := nasStep(t, enbID, ueID, "identity_response")
	if got := jsonGet(auth, "nas.message_type"); got != "authentication_request" {
		t.Fatalf("after Identity Response, nas.message_type = %q, want authentication_request; body: %s", got, auth)
	}
}
