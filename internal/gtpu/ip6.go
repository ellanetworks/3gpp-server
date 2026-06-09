package gtpu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
)

// IPv6 next-header / ICMPv6 type values.
const (
	protoICMPv6 = 58

	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

// checksum6 computes the upper-layer checksum over the IPv6 pseudo-header
// (RFC 8200 §8.1) and the upper-layer message. The message's own checksum field
// must be zero on input.
func checksum6(src, dst netip.Addr, nextHeader uint8, upper []byte) uint16 {
	pseudo := make([]byte, 40+len(upper))

	s := src.As16()
	d := dst.As16()
	copy(pseudo[0:16], s[:])
	copy(pseudo[16:32], d[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(upper)))
	pseudo[39] = nextHeader
	copy(pseudo[40:], upper)

	return onesComplementSum(pseudo)
}

// buildIPv6 wraps an upper-layer message in an IPv6 header.
func buildIPv6(nextHeader uint8, src, dst netip.Addr, upper []byte) []byte {
	ip := make([]byte, 40+len(upper))
	ip[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(upper)))
	ip[6] = nextHeader
	ip[7] = 64 // hop limit

	s := src.As16()
	d := dst.As16()
	copy(ip[8:24], s[:])
	copy(ip[24:40], d[:])
	copy(ip[40:], upper)

	return ip
}

// buildICMPv6Echo builds an ICMPv6 Echo Request from src to dst.
func buildICMPv6Echo(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = icmpv6EchoRequest
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], checksum6(src, dst, protoICMPv6, icmp))

	return buildIPv6(protoICMPv6, src, dst, icmp)
}

// buildUDPv6 builds a UDP-over-IPv6 datagram. The UDP checksum is mandatory over
// IPv6 (RFC 8200); a computed zero is transmitted as 0xffff (RFC 768).
func buildUDPv6(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	cs := checksum6(src, dst, protoUDP, udp)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], cs)

	return buildIPv6(protoUDP, src, dst, udp)
}

// ParseIPv6 decodes an IPv6 packet for assertion. It reads the upper-layer
// header directly (no extension-header walk — sufficient for the crafted test
// traffic). It returns an error for non-IPv6 or truncated input.
func ParseIPv6(b []byte) (*InnerPacket, error) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return nil, fmt.Errorf("not an IPv6 packet")
	}

	src, _ := netip.AddrFromSlice(b[8:24])
	dst, _ := netip.AddrFromSlice(b[24:40])

	p := &InnerPacket{
		Src:      src.String(),
		Dst:      dst.String(),
		Protocol: b[6],
	}

	l4 := b[40:]

	switch b[6] {
	case protoICMPv6:
		if len(l4) >= 8 {
			p.ICMPType = l4[0]
			p.ICMPID = binary.BigEndian.Uint16(l4[4:6])
			p.ICMPSeq = binary.BigEndian.Uint16(l4[6:8])
		}
	case protoUDP:
		if len(l4) >= 8 {
			p.UDPSrcPort = binary.BigEndian.Uint16(l4[0:2])
			p.UDPDstPort = binary.BigEndian.Uint16(l4[2:4])
			p.Payload = hex.EncodeToString(l4[8:])
		}
	}

	return p, nil
}

// ParseInner decodes an inner T-PDU, dispatching on the IP version.
func ParseInner(b []byte) (*InnerPacket, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("empty packet")
	}

	switch b[0] >> 4 {
	case 4:
		return ParseIPv4(b)
	case 6:
		return ParseIPv6(b)
	default:
		return nil, fmt.Errorf("unknown IP version %d", b[0]>>4)
	}
}
