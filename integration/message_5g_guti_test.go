// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"strconv"
	"testing"
)

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

	tmsi := jsonGet(accept, "nas.guti.5g_tmsi")
	if tmsi == "" {
		t.Fatalf("Registration Accept carries no 5G-GUTI; reallocation is part of every initial registration (TS 24.501 §5.5.1.2.4)\n  body: %s", accept)
	}

	assertRegistrationAcceptTAIList(t, accept)

	if status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_complete"}`); status != 200 {
		t.Fatalf("registration_complete: HTTP %d\n  body: %s", status, body)
	}

	return tmsi
}

func Test5GGUTIReallocation(t *testing.T) {
	gnbID := mustCreateGnB(t)

	const n = 4

	var (
		seen  = make(map[string]bool, n)
		tmsis []uint64
	)

	for i := 0; i < n; i++ {
		tmsi := registerToAccept(t, gnbID)

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
