//go:build integration

// Raw-NGAP fuzz coverage: feed the AMF deliberately malformed NGAP PDUs and
// assert it rejects them without crashing. A crash here is a core defect.

package integration_test

import (
	"fmt"
	"testing"
)

// sendRawNGAP writes raw (hex) bytes onto the gNB's N2 association.
func sendRawNGAP(t *testing.T, gnbID, pduHex string) {
	t.Helper()

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap",
		fmt.Sprintf(`{"raw_ngap_pdu":%q}`, pduHex))
	if status != 200 {
		t.Fatalf("raw_ngap_pdu send on gnb %s: HTTP %d\n  body: %s", gnbID, status, body)
	}
}

// Each case feeds the AMF a malformed PDU, then verifies the core still serves
// by completing a fresh NG Setup. Failure means the malformed input killed it.
func TestRawNGAPMalformedDoesNotCrashCore(t *testing.T) {
	cases := []struct {
		name string
		hex  string
	}{
		{"single zero byte", "00"},
		{"random garbage", "deadbeefcafebabe"},
		{"truncated initiating message", "0015"},
		{"bogus procedure code", "00ff000400000000"},
		{"all ones", "ffffffffffffffffffffffff"},
		{"plausible header, junk body", "000e80808080"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gnbID := createGnBWithID(t, fmt.Sprintf("%06x", 0x100+i), "fuzz-src")
			sendRawNGAP(t, gnbID, tc.hex)

			// Liveness probe: a fresh gNB completing NG Setup proves the core survived.
			createGnBWithID(t, fmt.Sprintf("%06x", 0x200+i), "fuzz-probe")
		})
	}
}
