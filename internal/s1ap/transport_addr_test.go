// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import "testing"

func TestBuildInitialContextSetupResponseValidAddr(t *testing.T) {
	b, err := BuildInitialContextSetupResponse(InitialContextSetupResponseParams{
		MMEUES1APID: 1,
		ENBUES1APID: 2,
		ERABID:      5,
		ENBN3Addr:   "10.0.0.1",
		GTPTEID:     0x01020304,
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if len(b) == 0 {
		t.Fatal("expected non-empty encoded message, got empty")
	}
}

func TestBuildInitialContextSetupResponseInvalidAddr(t *testing.T) {
	for _, addr := range []string{"", "not-an-ip"} {
		_, err := BuildInitialContextSetupResponse(InitialContextSetupResponseParams{
			MMEUES1APID: 1,
			ENBUES1APID: 2,
			ERABID:      5,
			ENBN3Addr:   addr,
			GTPTEID:     0x01020304,
		})
		if err == nil {
			t.Fatalf("expected error for address %q, got nil", addr)
		}
	}
}

func TestParseTransportAddrIPv4Is4Byte(t *testing.T) {
	ip, err := parseTransportAddr("192.168.1.1")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	if len(ip) != 4 {
		t.Fatalf("expected 4-byte IPv4 form, got %d bytes", len(ip))
	}
}
