// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package gtpu

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Expected values are computed by hand from RFC 1071, not captured from this implementation.
func TestOnesComplementSum(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want uint16
	}{
		{
			name: "RFC 1071 §3 example vector",
			in:   []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7},
			want: 0x220d,
		},
		{
			name: "no carry",
			in:   []byte{0x00, 0x01, 0x00, 0x02},
			want: 0xfffc,
		},
		{
			name: "single carry fold",
			in:   []byte{0xff, 0xff, 0xff, 0xff},
			want: 0x0000,
		},
		{
			name: "carry fold repeats",
			in:   []byte{0xff, 0xff, 0xff, 0xff, 0x00, 0x01},
			want: 0xfffe,
		},
		{
			name: "odd length pads trailing byte with zero",
			in:   []byte{0x12, 0x34, 0x56},
			want: 0x97cb,
		},
		{
			name: "empty",
			in:   nil,
			want: 0xffff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := onesComplementSum(tt.in); got != tt.want {
				t.Errorf("onesComplementSum(%x) = %#04x, want %#04x", tt.in, got, tt.want)
			}
		})
	}
}

func TestOnesComplementSumOddLengthMatchesZeroPad(t *testing.T) {
	odd := []byte{0x45, 0x00, 0x00, 0x27, 0xab}
	padded := []byte{0x45, 0x00, 0x00, 0x27, 0xab, 0x00}

	if got, want := onesComplementSum(odd), onesComplementSum(padded); got != want {
		t.Errorf("onesComplementSum(%x) = %#04x, want %#04x (the zero-padded buffer)", odd, got, want)
	}
}

func TestBuildICMPv4Echo_RoundTrip(t *testing.T) {
	src := mustAddr(t, "10.45.0.1")
	dst := mustAddr(t, "8.8.8.8")

	pkt, err := BuildICMPEcho(src, dst, 0x1234, 7, []byte("3gpp-server"))
	if err != nil {
		t.Fatalf("BuildICMPEcho v4: %v", err)
	}

	if len(pkt) != 39 {
		t.Fatalf("packet length = %d, want 39", len(pkt))
	}

	// Hand-computed per RFC 791, not captured from this implementation.
	wantHeader := "450000270000000040016099" + "0a2d0001" + "08080808"
	if got := hex.EncodeToString(pkt[:20]); got != wantHeader {
		t.Errorf("IPv4 header = %s, want %s", got, wantHeader)
	}

	if cs := onesComplementSum(pkt[:20]); cs != 0 {
		t.Errorf("IPv4 header checksum does not validate: folds to %#04x, want 0", cs)
	}

	if cs := binary.BigEndian.Uint16(pkt[22:24]); cs != 0xc6a1 {
		t.Errorf("ICMP checksum = %#04x, want %#04x", cs, 0xc6a1)
	}
	if cs := onesComplementSum(pkt[20:]); cs != 0 {
		t.Errorf("ICMP checksum does not validate: folds to %#04x, want 0", cs)
	}

	p, err := ParseInner(pkt)
	if err != nil {
		t.Fatalf("ParseInner: %v", err)
	}

	if p.Src != src.String() || p.Dst != dst.String() {
		t.Errorf("addresses = %s -> %s, want %s -> %s", p.Src, p.Dst, src, dst)
	}
	if p.Protocol != protoICMP {
		t.Errorf("protocol = %d, want %d (ICMP)", p.Protocol, protoICMP)
	}
	if p.ICMPType != icmpEchoRequest {
		t.Errorf("ICMP type = %d, want %d (ICMP Echo Request)", p.ICMPType, icmpEchoRequest)
	}
	if p.ICMPID != 0x1234 || p.ICMPSeq != 7 {
		t.Errorf("id/seq = %d/%d, want 4660/7", p.ICMPID, p.ICMPSeq)
	}
}

func TestBuildUDPv4_RoundTrip(t *testing.T) {
	src := mustAddr(t, "10.45.0.1")
	dst := mustAddr(t, "8.8.8.8")

	payload := []byte{0xab, 0xad, 0x1d, 0xea}

	pkt, err := BuildUDP(src, dst, 12345, 7, payload)
	if err != nil {
		t.Fatalf("BuildUDP v4: %v", err)
	}

	// Hand-computed per RFC 791, not captured from this implementation.
	wantHeader := "450000200000000040116090" + "0a2d0001" + "08080808"
	if got := hex.EncodeToString(pkt[:20]); got != wantHeader {
		t.Errorf("IPv4 header = %s, want %s", got, wantHeader)
	}

	if cs := onesComplementSum(pkt[:20]); cs != 0 {
		t.Errorf("IPv4 header checksum does not validate: folds to %#04x, want 0", cs)
	}

	// The UDP checksum is optional over IPv4; zero marks it as not computed (RFC 768).
	if cs := binary.BigEndian.Uint16(pkt[26:28]); cs != 0 {
		t.Errorf("UDP checksum = %#04x, want 0 (not computed)", cs)
	}

	if l := binary.BigEndian.Uint16(pkt[24:26]); l != 12 {
		t.Errorf("UDP length = %d, want 12", l)
	}

	p, err := ParseInner(pkt)
	if err != nil {
		t.Fatalf("ParseInner: %v", err)
	}

	if p.Protocol != protoUDP {
		t.Errorf("protocol = %d, want %d (UDP)", p.Protocol, protoUDP)
	}
	if p.UDPSrcPort != 12345 || p.UDPDstPort != 7 {
		t.Errorf("ports = %d -> %d, want 12345 -> 7", p.UDPSrcPort, p.UDPDstPort)
	}
	if p.Payload != hex.EncodeToString(payload) {
		t.Errorf("payload = %s, want %s", p.Payload, hex.EncodeToString(payload))
	}
}
