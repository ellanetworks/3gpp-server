// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"strconv"
	"testing"
)

// The 5G-TMSI is the last 4 of the 11 octets of a 5GS mobile identity carrying a
// 5G-GUTI (TS 24.501 §9.11.3.4).
func guti5GTMSI(t *testing.T, guti string) string {
	t.Helper()

	const gutiHexLen = 22

	if len(guti) != gutiHexLen {
		t.Fatalf("5G-GUTI %q is %d hex chars, want %d — an 11-octet 5GS mobile identity (TS 24.501 §9.11.3.4)", guti, len(guti), gutiHexLen)
	}

	return guti[gutiHexLen-8:]
}

func registerToAccept(t *testing.T, gnbID string) string {
	t.Helper()

	ueID := mustCreateUE(t, gnbID)

	for _, step := range []string{"registration_request", "authentication_response"} {
		if status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"`+step+`"}`); status != 200 {
			t.Fatalf("%s: HTTP %d\n  body: %s", step, status, body)
		}
	}

	status, accept := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"security_mode_complete"}`)
	if status != 200 {
		t.Fatalf("security_mode_complete: HTTP %d\n  body: %s", status, accept)
	}

	if got := jsonGet(accept, "nas.message_type"); got != nasRegistrationAccept {
		t.Fatalf("nas.message_type = %q, want registration_accept\n  body: %s", got, accept)
	}

	guti := jsonGet(accept, "nas.guti")
	if guti == "" {
		t.Fatalf("Registration Accept carries no 5G-GUTI; reallocation is part of every initial registration (TS 24.501 §5.5.1.2.4)\n  body: %s", accept)
	}

	if status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_complete"}`); status != 200 {
		t.Fatalf("registration_complete: HTTP %d\n  body: %s", status, body)
	}

	return guti
}

func Test5GGUTIReallocation(t *testing.T) {
	gnbID := mustCreateGnB(t)

	const n = 4

	var (
		seen  = make(map[string]bool, n)
		tmsis []uint64
	)

	for i := 0; i < n; i++ {
		tmsi := guti5GTMSI(t, registerToAccept(t, gnbID))

		if seen[tmsi] {
			t.Fatalf("registration %d: 5G-TMSI %s reused; each initial registration must carry a newly assigned 5G-GUTI (TS 24.501 §5.5.1.2.4)", i, tmsi)
		}

		seen[tmsi] = true

		v, err := strconv.ParseUint(tmsi, 16, 32)
		if err != nil {
			t.Fatalf("5G-TMSI %q not a 32-bit hex value: %v", tmsi, err)
		}

		tmsis = append(tmsis, v)
	}

	assertUnpredictableTMSIs(t, tmsis, "5G-TMSI", "TS 33.501 §6.12.3")
}
