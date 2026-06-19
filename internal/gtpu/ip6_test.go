// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package gtpu

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()

	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}

	return a
}

// TestBuildICMPv6Echo_RoundTrip builds an ICMPv6 Echo Request, parses it back,
// and confirms the fields and a valid (zero-folding) checksum.
func TestBuildICMPv6Echo_RoundTrip(t *testing.T) {
	src := mustAddr(t, "fd00:45::1")
	dst := mustAddr(t, "fd00:6::10")

	pkt, err := BuildICMPEcho(src, dst, 0x1234, 7, []byte("3gpp-server"))
	if err != nil {
		t.Fatalf("BuildICMPEcho v6: %v", err)
	}

	if pkt[0]>>4 != 6 {
		t.Fatalf("not an IPv6 packet: version nibble %d", pkt[0]>>4)
	}

	// The ICMPv6 checksum (computed over the pseudo-header with the field
	// included) must fold to zero.
	if cs := checksum6(src, dst, protoICMPv6, pkt[40:]); cs != 0 {
		t.Errorf("ICMPv6 checksum does not validate: folds to %#04x, want 0", cs)
	}

	p, err := ParseInner(pkt)
	if err != nil {
		t.Fatalf("ParseInner: %v", err)
	}

	if p.Src != src.String() || p.Dst != dst.String() {
		t.Errorf("addresses = %s -> %s, want %s -> %s", p.Src, p.Dst, src, dst)
	}
	if p.Protocol != protoICMPv6 {
		t.Errorf("protocol = %d, want %d (ICMPv6)", p.Protocol, protoICMPv6)
	}
	if p.ICMPType != icmpv6EchoRequest {
		t.Errorf("ICMP type = %d, want %d (ICMPv6 Echo Request)", p.ICMPType, icmpv6EchoRequest)
	}
	if p.ICMPID != 0x1234 || p.ICMPSeq != 7 {
		t.Errorf("id/seq = %d/%d, want 4660/7", p.ICMPID, p.ICMPSeq)
	}
}

// TestBuildUDPv6_RoundTrip builds a UDP-over-IPv6 datagram, parses it back, and
// confirms the mandatory checksum validates and the payload survives.
func TestBuildUDPv6_RoundTrip(t *testing.T) {
	src := mustAddr(t, "fd00:45::1")
	dst := mustAddr(t, "fd00:6::10")

	payload := []byte{0xab, 0xad, 0x1d, 0xea}

	pkt, err := BuildUDP(src, dst, 12345, 7, payload)
	if err != nil {
		t.Fatalf("BuildUDP v6: %v", err)
	}

	if cs := checksum6(src, dst, protoUDP, pkt[40:]); cs != 0 {
		t.Errorf("UDP-over-IPv6 checksum does not validate: folds to %#04x, want 0", cs)
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

// TestBuildMismatchedFamilies rejects a mixed IPv4/IPv6 address pair.
func TestBuildMismatchedFamilies(t *testing.T) {
	v4 := mustAddr(t, "10.45.0.1")
	v6 := mustAddr(t, "fd00:6::10")

	if _, err := BuildICMPEcho(v4, v6, 1, 1, nil); err == nil {
		t.Error("BuildICMPEcho with mismatched families: want error, got nil")
	}
	if _, err := BuildUDP(v6, v4, 1, 1, nil); err == nil {
		t.Error("BuildUDP with mismatched families: want error, got nil")
	}
}

// TestParseInnerDispatch confirms version dispatch for IPv4 and IPv6.
func TestParseInnerDispatch(t *testing.T) {
	v4, err := BuildICMPEcho(mustAddr(t, "10.45.0.1"), mustAddr(t, "8.8.8.8"), 1, 1, nil)
	if err != nil {
		t.Fatalf("build v4: %v", err)
	}
	if p, err := ParseInner(v4); err != nil || p.Protocol != protoICMP {
		t.Errorf("ParseInner(v4) = %+v, %v; want ICMP", p, err)
	}

	v6, err := BuildICMPEcho(mustAddr(t, "fd00:45::1"), mustAddr(t, "fd00:6::10"), 1, 1, nil)
	if err != nil {
		t.Fatalf("build v6: %v", err)
	}
	if p, err := ParseInner(v6); err != nil || p.Protocol != protoICMPv6 {
		t.Errorf("ParseInner(v6) = %+v, %v; want ICMPv6", p, err)
	}
}
