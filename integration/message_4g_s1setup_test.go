// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	s1ap "github.com/ellanetworks/3gpp-server/internal/s1ap"
)

const (
	mmeAddress   = "10.3.0.2:36412"
	enbS1Address = "10.3.0.3"
)

// createENBRaw opens an S1-MME association and sends rawHex verbatim as the first
// PDU, then returns the HTTP status and body. Registers cleanup of the eNB.
func createENBRaw(t *testing.T, rawHex string) (int, []byte) {
	t.Helper()

	// A malformed PDU is usually dropped without reply, so cap the wait low to
	// keep the adversarial sweep within the suite timeout.
	body := fmt.Sprintf(`{
		"mme_address": %q,
		"enb_s1_address": %q,
		"raw_s1ap_pdu": %q,
		"timeout_ms": 800
	}`, mmeAddress, enbS1Address, rawHex)

	status, resp := doRequest(t, "POST", "/enb", body)
	if id := jsonGet(resp, "enb_id"); id != "" {
		t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })
	}

	return status, resp
}

// validS1SetupPDU returns a well-formed S1 Setup Request as hex, used as the seed
// for byte-level corruption.
func validS1SetupPDU(t *testing.T) []byte {
	t.Helper()

	b, err := s1ap.BuildS1SetupRequest(&s1ap.S1SetupRequestParams{
		MCC: "001", MNC: "01", ENBID: 7, ENBName: "fuzz-seed", TAC: 1,
	})
	if err != nil {
		t.Fatalf("build seed S1 Setup: %v", err)
	}

	return b
}

// sendS1SetupPDU builds an S1 Setup Request from p, sends it on a fresh
// association, and returns the response body. The wait is long enough for a
// definite MME reply (these PDUs are well-formed, so the MME must answer).
// Registers cleanup of the eNB.
func sendS1SetupPDU(t *testing.T, p *s1ap.S1SetupRequestParams) []byte {
	t.Helper()

	pdu, err := s1ap.BuildS1SetupRequest(p)
	if err != nil {
		t.Fatalf("build S1 Setup: %v", err)
	}

	body := fmt.Sprintf(`{"mme_address":%q,"enb_s1_address":%q,"raw_s1ap_pdu":%q,"timeout_ms":3000}`,
		mmeAddress, enbS1Address, hex.EncodeToString(pdu))

	status, resp := doRequest(t, "POST", "/enb", body)
	if id := jsonGet(resp, "enb_id"); id != "" {
		t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })
	}

	if status != 201 {
		t.Fatalf("create enb (raw): HTTP %d: %s", status, resp)
	}

	return resp
}

// assertS1SetupAccepted checks the MME returned an S1 Setup Response carrying its
// mandatory Served GUMMEIs IE (TS 36.413 §9.1.8.5).
func assertS1SetupAccepted(t *testing.T, resp []byte) {
	t.Helper()

	if got := jsonGet(resp, "response.message_type"); got != "S1SetupResponse" {
		t.Fatalf("message_type = %q, want S1SetupResponse; body: %s", got, resp)
	}

	if g := jsonGet(resp, "response.s1_setup_response.served_gummeis"); g == "" || g == "null" || g == "[]" {
		t.Fatalf("S1 Setup Response missing mandatory Served GUMMEIs (TS 36.413 §9.1.8.5); body: %s", resp)
	}
}

// assertS1SetupRejected checks the MME returned an S1 Setup Failure carrying its
// mandatory Cause IE (TS 36.413 §9.1.8.6). The specific cause is left unchecked:
// §8.7.3.4 gives "Unknown PLMN" only as an example ("e.g.").
func assertS1SetupRejected(t *testing.T, resp []byte) {
	t.Helper()

	if got := jsonGet(resp, "response.message_type"); got != "S1SetupFailure" {
		t.Fatalf("message_type = %q, want S1SetupFailure; body: %s", got, resp)
	}

	if c := jsonGet(resp, "response.s1_setup_failure.cause.group"); c == "" {
		t.Fatalf("S1 Setup Failure missing mandatory Cause (TS 36.413 §9.1.8.6); body: %s", resp)
	}
}

// TestS1SetupHappyVariations checks the MME accepts a range of valid eNB
// configurations, all yielding an S1 Setup Response.
func Test4GS1SetupHappyVariations(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"baseline", `"mcc":"001","mnc":"01","tac":"0001","enb_id":1,"name":"enb-baseline"`},
		{"different eNB ID", `"mcc":"001","mnc":"01","tac":"0001","enb_id":1048575,"name":"enb-max-macro"`},
		{"different TAC", `"mcc":"001","mnc":"01","tac":"abcd","enb_id":2,"name":"enb-tac"`},
		{"no name (optional omitted)", `"mcc":"001","mnc":"01","tac":"0001","enb_id":3`},
		{"long name", `"mcc":"001","mnc":"01","tac":"0001","enb_id":4,"name":"this-is-a-very-long-enb-name-used-for-testing-the-printable-string-bound"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"mme_address":%q,"enb_s1_address":%q,%s}`, mmeAddress, enbS1Address, tt.body)

			status, resp := doRequest(t, "POST", "/enb", body)
			if id := jsonGet(resp, "enb_id"); id != "" {
				t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })
			}

			if status != 201 {
				t.Fatalf("HTTP %d: %s", status, resp)
			}

			assertS1SetupAccepted(t, resp)
		})
	}
}

// TestS1SetupWrongPLMN checks the MME refuses an eNB none of whose PLMNs it
// serves. TS 36.413 §8.7.3.4 mandates this: "none of the PLMNs provided by the
// eNB is identified by the MME, then the MME shall reject the eNB S1 Setup
// Request procedure with the appropriate cause value, e.g. 'Unknown PLMN'." The
// cause is exemplary ("e.g."), so only the S1 Setup Failure outcome is asserted.
func Test4GS1SetupWrongPLMN(t *testing.T) {
	tests := []struct {
		name     string
		mcc, mnc string
	}{
		{"wrong MCC", "999", "01"},
		{"wrong MNC", "001", "99"},
		{"foreign PLMN", "310", "410"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"mme_address":%q,"enb_s1_address":%q,"mcc":%q,"mnc":%q,"tac":"0001","enb_id":1,"name":"enb-wrong-plmn"}`,
				mmeAddress, enbS1Address, tt.mcc, tt.mnc)

			status, resp := doRequest(t, "POST", "/enb", body)
			if id := jsonGet(resp, "enb_id"); id != "" {
				t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })
			}

			if status != 201 {
				t.Fatalf("HTTP %d: %s", status, resp)
			}

			assertS1SetupRejected(t, resp)
		})
	}
}

// TestS1SetupMalformed throws PDUs that cannot be a valid S1 Setup at the MME
// and verifies it never mistakes one for a Response. These inputs are either
// incomplete (truncated) or not S1AP at all, so the only correct outcomes are a
// silent drop (null response), an Error Indication, or a Failure. Ambiguous
// corruptions that might still decode to a valid Setup are exercised by
// TestS1SetupResilience instead.
func Test4GS1SetupMalformed(t *testing.T) {
	seed := validS1SetupPDU(t)

	cases := map[string][]byte{
		"one byte":      {0x00},
		"ff byte":       {0xff},
		"short garbage": {0xde, 0xad, 0xbe, 0xef},
		"long ff run":   bytesRepeat(0xff, 64),
	}

	for n := 1; n < len(seed); n += max(1, len(seed)/4) {
		cases[fmt.Sprintf("truncated to %d", n)] = cloneBytes(seed[:n])
	}

	for name, pdu := range cases {
		t.Run(name, func(t *testing.T) {
			status, resp := createENBRaw(t, hex.EncodeToString(pdu))
			if status != 201 {
				t.Fatalf("server failed to handle raw send (HTTP %d): %s", status, resp)
			}

			if got := jsonGet(resp, "response.message_type"); got == "S1SetupResponse" {
				t.Fatalf("MME accepted malformed PDU as S1 Setup; body: %s", resp)
			}
		})
	}
}

// TestS1SetupResilience drives a barrage of corrupted and oversized PDUs — any
// MME outcome is acceptable, including accepting a flip that happens to stay
// valid — then confirms a fresh eNB still completes S1 Setup, proving the MME
// stayed on its feet.
func Test4GS1SetupResilience(t *testing.T) {
	seed := validS1SetupPDU(t)

	barrage := [][]byte{
		append(cloneBytes(seed), seed...),
		append(cloneBytes(seed), bytesRepeat(0xff, 8)...),
		append([]byte{0x00}, seed...),
		bytesRepeat(0x41, 4096),
	}

	// Sample byte positions across the seed rather than every byte, keeping the
	// barrage bounded while still hitting the envelope, IE headers, and payload.
	for n := 0; n < len(seed); n += max(1, len(seed)/12) {
		barrage = append(barrage, flipByte(seed, n))
	}

	for _, pdu := range barrage {
		createENBRaw(t, hex.EncodeToString(pdu))
	}

	enbID := mustCreateENB(t)

	status, resp := doRequest(t, "GET", "/enb/"+enbID, "")
	if status != 200 {
		t.Fatalf("eNB unhealthy after barrage: HTTP %d: %s", status, resp)
	}
}

// TestS1SetupPLMNFlex exercises the precise boundary of TS 36.413 §8.7.3.4,
// which rejects only when *none* of the eNB's broadcast PLMNs is served. An eNB
// broadcasting several PLMNs of which one is served (S1-flex / RAN sharing) must
// be accepted; one broadcasting only unserved PLMNs must be rejected.
func Test4GS1SetupPLMNFlex(t *testing.T) {
	served := s1ap.PLMNParams{MCC: "001", MNC: "01"}
	foreignA := s1ap.PLMNParams{MCC: "310", MNC: "410"}
	foreignB := s1ap.PLMNParams{MCC: "999", MNC: "01"}

	t.Run("one served among several is accepted", func(t *testing.T) {
		resp := sendS1SetupPDU(t, &s1ap.S1SetupRequestParams{
			MCC: "001", MNC: "01", ENBID: 0x100, ENBName: "enb-flex-match",
			SupportedTAs: []s1ap.SupportedTAParams{{
				TAC:            1,
				BroadcastPLMNs: []s1ap.PLMNParams{foreignA, served, foreignB},
			}},
		})
		assertS1SetupAccepted(t, resp)
	})

	t.Run("none served is rejected", func(t *testing.T) {
		resp := sendS1SetupPDU(t, &s1ap.S1SetupRequestParams{
			MCC: "310", MNC: "410", ENBID: 0x101, ENBName: "enb-flex-none",
			SupportedTAs: []s1ap.SupportedTAParams{{
				TAC:            1,
				BroadcastPLMNs: []s1ap.PLMNParams{foreignA, foreignB},
			}},
		})
		assertS1SetupRejected(t, resp)
	})
}

// TestS1SetupENBIDVariants checks the MME accepts every Global eNB ID encoding
// (TS 36.413 §9.2.1.37): macro (20-bit), home (28-bit), short-macro (18-bit),
// and long-macro (21-bit), each at its maximum value.
func Test4GS1SetupENBIDVariants(t *testing.T) {
	tests := []struct {
		name string
		kind s1ap.ENBIDKind
		id   uint32
	}{
		{"macro 20-bit", s1ap.ENBIDMacro, 0x0FFFFF},
		{"home 28-bit", s1ap.ENBIDHome, 0xFFFFFFF},
		{"short-macro 18-bit", s1ap.ENBIDShortMacro, 0x3FFFF},
		{"long-macro 21-bit", s1ap.ENBIDLongMacro, 0x1FFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sendS1SetupPDU(t, &s1ap.S1SetupRequestParams{
				MCC: "001", MNC: "01", ENBID: tt.id, ENBIDKind: tt.kind,
				ENBName: "enb-" + strings.ReplaceAll(tt.name, " ", "-"), TAC: 1,
			})
			assertS1SetupAccepted(t, resp)
		})
	}
}

// TestS1SetupSupportedTAs checks the MME accepts an eNB advertising several
// supported TAs and a maximum-length eNB Name (TS 36.413 §9.1.8.4; the eNB Name
// is a PrintableString of SIZE(1..150)).
func Test4GS1SetupSupportedTAs(t *testing.T) {
	t.Run("multiple TAs", func(t *testing.T) {
		resp := sendS1SetupPDU(t, &s1ap.S1SetupRequestParams{
			MCC: "001", MNC: "01", ENBID: 0x200, ENBName: "enb-multi-ta",
			SupportedTAs: []s1ap.SupportedTAParams{
				{TAC: 1}, {TAC: 2}, {TAC: 0xABCD},
			},
		})
		assertS1SetupAccepted(t, resp)
	})

	t.Run("max-length eNB name", func(t *testing.T) {
		resp := sendS1SetupPDU(t, &s1ap.S1SetupRequestParams{
			MCC: "001", MNC: "01", ENBID: 0x201, TAC: 1,
			ENBName: strings.Repeat("e", 150),
		})
		assertS1SetupAccepted(t, resp)
	})
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)

	return out
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}

	return out
}

func flipByte(b []byte, i int) []byte {
	out := cloneBytes(b)
	if i >= 0 && i < len(out) {
		out[i] ^= 0xff
	}

	return out
}
