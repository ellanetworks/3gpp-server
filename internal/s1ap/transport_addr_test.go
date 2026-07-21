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

func TestTransportLayerIPs(t *testing.T) {
	v4 := []byte{10, 3, 0, 2}
	v6 := []byte{0xfd, 0x00, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	cases := []struct {
		name   string
		in     []byte
		wantV4 string
		wantV6 string
	}{
		{"32 bits: IPv4 only", v4, "10.3.0.2", ""},
		{"128 bits: IPv6 only", v6, "", "fd00:3::2"},
		{"160 bits: IPv4 in the first 32 bits, then IPv6", append(append([]byte{}, v4...), v6...), "10.3.0.2", "fd00:3::2"},
		{"unspecified length", []byte{1, 2, 3}, "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotV4, gotV6 := transportLayerIPs(tc.in)
			if gotV4 != tc.wantV4 {
				t.Errorf("ipv4 = %q, want %q", gotV4, tc.wantV4)
			}

			if gotV6 != tc.wantV6 {
				t.Errorf("ipv6 = %q, want %q", gotV6, tc.wantV6)
			}
		})
	}
}
