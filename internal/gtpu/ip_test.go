// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package gtpu

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestOnesComplementSum checks the RFC 1071 rule: the 16-bit one's complement of
// the one's complement sum, with end-around carry folding and a trailing odd byte
// padded with a zero byte. Expected values are computed by hand.
func TestOnesComplementSum(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want uint16
	}{
		{
			// RFC 1071 §3 worked example; the RFC publishes sum 0xddf2, checksum 0x220d.
			name: "RFC 1071 example vector",
			in:   []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7},
			want: 0x220d,
		},
		{
			// 0x0001 + 0x0002 = 0x0003; ^0x0003 = 0xfffc.
			name: "no carry",
			in:   []byte{0x00, 0x01, 0x00, 0x02},
			want: 0xfffc,
		},
		{
			// 0xffff + 0xffff = 0x1fffe; fold once to 0xffff; ^0xffff = 0x0000.
			name: "single carry fold",
			in:   []byte{0xff, 0xff, 0xff, 0xff},
			want: 0x0000,
		},
		{
			// 0xffff + 0xffff + 0x0001 = 0x1ffff; folds to 0x10000, which must fold
			// again to 0x0001; ^0x0001 = 0xfffe.
			name: "carry fold repeats",
			in:   []byte{0xff, 0xff, 0xff, 0xff, 0x00, 0x01},
			want: 0xfffe,
		},
		{
			// Odd length: 0x1234 + 0x5600 = 0x6834; ^0x6834 = 0x97cb.
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

// TestOnesComplementSumOddLengthMatchesZeroPad confirms the trailing byte of an
// odd-length buffer contributes as the high-order byte of a zero-padded word
// (RFC 1071 §2), so padding explicitly changes nothing.
func TestOnesComplementSumOddLengthMatchesZeroPad(t *testing.T) {
	odd := []byte{0x45, 0x00, 0x00, 0x27, 0xab}
	padded := []byte{0x45, 0x00, 0x00, 0x27, 0xab, 0x00}

	if got, want := onesComplementSum(odd), onesComplementSum(padded); got != want {
		t.Errorf("onesComplementSum(%x) = %#04x, want %#04x (the zero-padded buffer)", odd, got, want)
	}
}

// TestBuildICMPv4Echo_RoundTrip builds an ICMP Echo Request, parses it back, and
// confirms the RFC 791 header fields, the hand-computed header and ICMP
// checksums, and a valid (zero-folding) header checksum.
func TestBuildICMPv4Echo_RoundTrip(t *testing.T) {
	src := mustAddr(t, "10.45.0.1")
	dst := mustAddr(t, "8.8.8.8")

	pkt, err := BuildICMPEcho(src, dst, 0x1234, 7, []byte("3gpp-server"))
	if err != nil {
		t.Fatalf("BuildICMPEcho v4: %v", err)
	}

	// 20-byte header (IHL 5) + 8-byte ICMP header + 11-byte payload.
	if len(pkt) != 39 {
		t.Fatalf("packet length = %d, want 39", len(pkt))
	}

	// Hand-computed per RFC 791: version 4/IHL 5, total length 39, TTL 64,
	// protocol 1, header checksum 0x6099 over the words of this header.
	wantHeader := "450000270000000040016099" + "0a2d0001" + "08080808"
	if got := hex.EncodeToString(pkt[:20]); got != wantHeader {
		t.Errorf("IPv4 header = %s, want %s", got, wantHeader)
	}

	// RFC 791: summing all 16-bit words of a header carrying a correct checksum
	// folds to zero.
	if cs := onesComplementSum(pkt[:20]); cs != 0 {
		t.Errorf("IPv4 header checksum does not validate: folds to %#04x, want 0", cs)
	}

	// Hand-computed over the 19-byte ICMP message (odd length, trailing byte
	// zero-padded) with the checksum field zero.
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

// TestBuildUDPv4_RoundTrip builds a UDP-over-IPv4 datagram, parses it back, and
// confirms the header checksum validates and the payload survives.
func TestBuildUDPv4_RoundTrip(t *testing.T) {
	src := mustAddr(t, "10.45.0.1")
	dst := mustAddr(t, "8.8.8.8")

	payload := []byte{0xab, 0xad, 0x1d, 0xea}

	pkt, err := BuildUDP(src, dst, 12345, 7, payload)
	if err != nil {
		t.Fatalf("BuildUDP v4: %v", err)
	}

	// Hand-computed per RFC 791: total length 32, protocol 17, header checksum
	// 0x6090 over the words of this header.
	wantHeader := "450000200000000040116090" + "0a2d0001" + "08080808"
	if got := hex.EncodeToString(pkt[:20]); got != wantHeader {
		t.Errorf("IPv4 header = %s, want %s", got, wantHeader)
	}

	if cs := onesComplementSum(pkt[:20]); cs != 0 {
		t.Errorf("IPv4 header checksum does not validate: folds to %#04x, want 0", cs)
	}

	// RFC 768 makes the UDP checksum optional over IPv4, and an all-zero field
	// marks it as not computed.
	if cs := binary.BigEndian.Uint16(pkt[26:28]); cs != 0 {
		t.Errorf("UDP checksum = %#04x, want 0 (not computed)", cs)
	}

	// RFC 768: the UDP length covers the UDP header and the payload.
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
