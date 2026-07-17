// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func sendRawS1APAwaitingErrorIndication(t *testing.T, enbID, pduHex, clause string) []byte {
	t.Helper()

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/s1ap",
		fmt.Sprintf(`{"raw_s1ap_pdu":%q,"wait_for":["ErrorIndication"],"timeout_ms":3000}`, pduHex))
	if status != 200 {
		t.Fatalf("raw_s1ap_pdu (%d octets) on enb %s: HTTP %d, want 200 — an Error Indication is required (TS 36.413 %s)\n  body: %s",
			len(pduHex)/2, enbID, status, clause, body)
	}

	return body
}

// TS 36.413 §8.7.2.2 requires at least one of the two IEs.
func assertS1APErrorIndicationReported(t *testing.T, body []byte, clause string) {
	t.Helper()

	if got := jsonGet(body, "s1ap.message_type"); got != "ErrorIndication" {
		t.Fatalf("s1ap.message_type = %q, want ErrorIndication (TS 36.413 %s)\n  body: %s", got, clause, body)
	}

	if jsonGet(body, "s1ap.cause.group") == "" && jsonGet(body, "s1ap.criticality_diagnostics") == "" {
		t.Errorf("ErrorIndication carries neither a Cause IE nor a Criticality Diagnostics IE; at least one is required (TS 36.413 §8.7.2.2)\n  body: %s", body)
	}
}

func Test4GRawS1APMalformedDoesNotCrashCore(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		// The clause governing the Error Indication, which turns on whether the
		// message decodes far enough to identify the procedure (TS 36.413 §10.3.4.1A).
		clause string
	}{
		// initiatingMessage, then the Procedure Code octet is absent.
		{"single zero byte", "00", "§10.2, §10.3.4.1A"},
		// de: the S1AP-PDU CHOICE extension bit is set, selecting an unknown alternative.
		{"random garbage", "deadbeefcafebabe", "§10.2, §10.3.4.1A"},
		// initiatingMessage, Procedure Code 17 (S1Setup), then the Criticality octet is absent.
		{"truncated initiating message", "0011", "§10.2"},
		// initiatingMessage, Procedure Code 255 (unallocated), Criticality "reject",
		// open type of length 4 over 4 octets: transfer syntax is intact.
		{"bogus procedure code", "00ff000400000000", "§10.3.4.1"},
		// ff: the S1AP-PDU CHOICE extension bit is set, selecting an unknown alternative.
		{"all ones", "ffffffffffffffffffffffff", "§10.2, §10.3.4.1A"},
		// initiatingMessage, Procedure Code 9 (InitialContextSetup), Criticality
		// "notify", open type declaring 128 octets over 1.
		{"plausible header, junk body", "000980808080", "§10.2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enbID := createENBWithID(t, claimENBID(), "fuzz-src")

			body := sendRawS1APAwaitingErrorIndication(t, enbID, tc.hex, tc.clause)
			assertS1APErrorIndicationReported(t, body, tc.clause)

			createENBWithID(t, claimENBID(), "fuzz-probe")
		})
	}
}
