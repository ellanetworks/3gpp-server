// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import "testing"

// TestTransportLayerIPs covers the three forms TS 36.414 §5.3 defines for a
// Transport Layer Address: "a) 32 bits in case of IPv4 address; b) 128 bits in
// case of IPv6 address; or c) 160 bits if both IPv4 and IPv6 addresses are
// signalled, in which case the IPv4 address is contained in the first 32 bits."
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
