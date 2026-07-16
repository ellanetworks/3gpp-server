// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"strconv"
	"testing"
)

// The PDN address IE opens with a spare-padded PDN type value (TS 24.301 §9.9.4.9).
func allocatedPDNType(t *testing.T, pdnAddress string, body []byte) int {
	t.Helper()

	if len(pdnAddress) < 2 {
		t.Fatalf("nas.pdn_address = %q, want at least a PDN type octet (TS 24.301 §9.9.4.9); body: %s", pdnAddress, body)
	}

	octet, err := strconv.ParseUint(pdnAddress[:2], 16, 8)
	if err != nil {
		t.Fatalf("nas.pdn_address = %q is not hex; body: %s", pdnAddress, body)
	}

	return int(octet & 0x07)
}

func attachWithPDNType(t *testing.T, enbID string, pdnType int) []byte {
	t.Helper()

	ueID := mustCreateENBUE(t, enbID)

	body := fmt.Sprintf(`{"message_type":"attach_request","pdn_type":%d}`, pdnType)
	if got := jsonGet(nasBody(t, enbID, ueID, body), "nas.message_type"); got != "authentication_request" {
		t.Fatalf("attach_request (pdn_type %d): got %q", pdnType, got)
	}

	nasStep(t, enbID, ueID, "authentication_response")

	return nasStep(t, enbID, ueID, "security_mode_complete")
}

func Test4GPDNTypeNegotiation(t *testing.T) {
	enbID := mustCreateENB(t)

	tests := []struct {
		name    string
		pdnType int
	}{
		{"IPv4", 1},
		{"IPv4v6", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accept := attachWithPDNType(t, enbID, tt.pdnType)

			if got := jsonGet(accept, "nas.message_type"); got != "attach_accept" {
				t.Fatalf("nas.message_type = %q, want attach_accept; body: %s", got, accept)
			}

			if jsonGet(accept, "nas.eps_bearer_identity") == "" {
				t.Fatalf("no default bearer established for PDN type %d; body: %s", tt.pdnType, accept)
			}

			c := jsonGet(accept, "nas.bearer_esm_cause")

			// #50 = IPv4 only, #51 = IPv6 only.
			if c != "" && c != "50" && c != "51" {
				t.Fatalf("bearer ESM cause = %q, want a PDN-type downgrade cause (50/51) or none; body: %s", c, accept)
			}

			if allocated := allocatedPDNType(t, jsonGet(accept, "nas.pdn_address"), accept); allocated != tt.pdnType && c == "" {
				t.Errorf("PDN type %d requested, %d allocated, bearer ESM cause absent; want an ESM cause (TS 24.301 §8.3.6.8); body: %s",
					tt.pdnType, allocated, accept)
			}
		})
	}
}
