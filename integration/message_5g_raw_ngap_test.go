// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func sendRawNGAPAwaitingErrorIndication(t *testing.T, gnbID, pduHex, clause string) []byte {
	t.Helper()

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap",
		fmt.Sprintf(`{"raw_ngap_pdu":%q,"wait_for":["ErrorIndication"],"timeout_ms":3000}`, pduHex))
	if status != 200 {
		t.Fatalf("raw_ngap_pdu (%d octets) on gnb %s: HTTP %d, want 200 — an Error Indication is required (TS 38.413 %s)\n  body: %s",
			len(pduHex)/2, gnbID, status, clause, body)
	}

	return body
}

// TS 38.413 §8.7.5.2 requires at least one of the two IEs; §9.2.6.13 makes both optional.
func assertErrorIndicationReported(t *testing.T, body []byte, clause string) {
	t.Helper()

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Fatalf("ngap.message_type = %q, want ErrorIndication (TS 38.413 %s)\n  body: %s", got, clause, body)
	}

	if !ngapHasCause(body) && ngapCriticalityDiagnostics(body) == nil {
		t.Errorf("ErrorIndication carries neither a Cause IE nor a Criticality Diagnostics IE; at least one is required (TS 38.413 §8.7.5.2)\n  body: %s", body)
	}
}

func Test5GRawNGAPMalformedDoesNotCrashCore(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		// The clause governing the Error Indication, which turns on whether the
		// Type of Message IE decodes (TS 38.413 §9.3.1.1).
		clause string
	}{
		// initiatingMessage, then the Procedure Code octet is absent.
		{"single zero byte", "00", "§10.2, §10.3.4.1A"},
		// de: the NGAP-PDU CHOICE extension bit is set, selecting an unknown alternative.
		{"random garbage", "deadbeefcafebabe", "§10.2, §10.3.4.1A"},
		// initiatingMessage, Procedure Code 21 (NGSetup), then the Criticality octet is absent.
		{"truncated initiating message", "0015", "§10.2"},
		// initiatingMessage, Procedure Code 255 (unallocated), Criticality "reject",
		// open type of length 4 over 4 octets: transfer syntax is intact.
		{"bogus procedure code", "00ff000400000000", "§10.3.4.1"},
		// ff: the NGAP-PDU CHOICE extension bit is set, selecting an unknown alternative.
		{"all ones", "ffffffffffffffffffffffff", "§10.2, §10.3.4.1A"},
		// initiatingMessage, Procedure Code 14 (InitialContextSetup), Criticality
		// "notify", open type declaring 128 octets over 1.
		{"plausible header, junk body", "000e80808080", "§10.2"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gnbID := createGNBWithID(t, fmt.Sprintf("%06x", 0x100+i), "fuzz-src")

			body := sendRawNGAPAwaitingErrorIndication(t, gnbID, tc.hex, tc.clause)
			assertErrorIndicationReported(t, body, tc.clause)

			createGNBWithID(t, fmt.Sprintf("%06x", 0x200+i), "fuzz-probe")
		})
	}
}
