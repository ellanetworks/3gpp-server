// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"strconv"
	"testing"
)

func attachToAccept(t *testing.T, enbID string) []byte {
	t.Helper()

	ueID := mustCreateENBUE(t, enbID)
	nasStep(t, enbID, ueID, "attach_request")
	nasStep(t, enbID, ueID, "authentication_response")

	return nasStep(t, enbID, ueID, "security_mode_complete")
}

func Test4GGUTIReallocation(t *testing.T) {
	enbID := mustCreateENB(t)

	const n = 4

	var (
		seen   = map[string]bool{}
		mtmsis []uint64
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
			t.Fatalf("M-TMSI %q not a 32-bit hex value: %v", mtmsi, err)
		}

		mtmsis = append(mtmsis, v)
	}

	assertUnpredictableTMSIs(t, mtmsis, "M-TMSI", "TS 33.401 §7.1")
}

func Test4GForeignGUTIIdentityRequest(t *testing.T) {
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
