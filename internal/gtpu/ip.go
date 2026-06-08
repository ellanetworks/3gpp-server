package gtpu

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// IP protocol numbers.
const (
	protoICMP = 1
	protoUDP  = 17
)

// ICMP types.
const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// onesComplementSum computes the 16-bit one's-complement checksum used by IPv4
// and ICMP.
func onesComplementSum(b []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}

	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// BuildICMPEcho builds an IPv4 ICMP Echo Request packet from src to dst with the
// given identifier, sequence, and payload.
func BuildICMPEcho(src, dst netip.Addr, id, seq uint16, payload []byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() {
		return nil, fmt.Errorf("ICMP echo requires IPv4 addresses")
	}

	icmp := make([]byte, 8+len(payload))
	icmp[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], onesComplementSum(icmp))

	return buildIPv4(protoICMP, src, dst, icmp), nil
}

// BuildUDP builds an IPv4 UDP packet from src:srcPort to dst:dstPort.
func BuildUDP(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() {
		return nil, fmt.Errorf("UDP build requires IPv4 addresses")
	}

	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	// UDP checksum is optional over IPv4; leave it zero.

	return buildIPv4(protoUDP, src, dst, udp), nil
}

func buildIPv4(proto uint8, src, dst netip.Addr, l4 []byte) []byte {
	total := 20 + len(l4)
	ip := make([]byte, total)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	ip[8] = 64 // TTL
	ip[9] = proto

	s := src.As4()
	d := dst.As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	binary.BigEndian.PutUint16(ip[10:12], onesComplementSum(ip[:20]))

	copy(ip[20:], l4)

	return ip
}

// InnerPacket is a decoded IPv4 packet, surfaced for assertions on a received
// downlink T-PDU.
type InnerPacket struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Protocol uint8  `json:"protocol"`

	// ICMP fields (when Protocol is ICMP). ICMPType is always surfaced so an Echo
	// Reply (type 0) is distinguishable.
	ICMPType uint8  `json:"icmp_type"`
	ICMPID   uint16 `json:"icmp_id,omitempty"`
	ICMPSeq  uint16 `json:"icmp_seq,omitempty"`

	Payload string `json:"payload,omitempty"` // hex of the L4 payload
}

// ParseIPv4 decodes an IPv4 packet for assertion. It returns an error for
// non-IPv4 or truncated input.
func ParseIPv4(b []byte) (*InnerPacket, error) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return nil, fmt.Errorf("not an IPv4 packet")
	}

	ihl := int(b[0]&0x0f) * 4
	if len(b) < ihl {
		return nil, fmt.Errorf("IPv4 header truncated")
	}

	src, _ := netip.AddrFromSlice(b[12:16])
	dst, _ := netip.AddrFromSlice(b[16:20])

	p := &InnerPacket{
		Src:      src.String(),
		Dst:      dst.String(),
		Protocol: b[9],
	}

	l4 := b[ihl:]

	switch b[9] {
	case protoICMP:
		if len(l4) >= 8 {
			p.ICMPType = l4[0]
			p.ICMPID = binary.BigEndian.Uint16(l4[4:6])
			p.ICMPSeq = binary.BigEndian.Uint16(l4[6:8])
		}
	}

	return p, nil
}

// IsICMPEchoReply reports whether the inner packet is an ICMP Echo Reply.
func (p *InnerPacket) IsICMPEchoReply() bool {
	return p.Protocol == protoICMP && p.ICMPType == icmpEchoReply
}
