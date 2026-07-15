// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package gtpu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
)

const (
	protoICMP = 1
	protoUDP  = 17
)

const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// onesComplementSum folds the end-around carry and pads a trailing odd byte as
// the high-order byte of a zero-padded word (RFC 1071 §2).
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

func BuildICMPEcho(src, dst netip.Addr, id, seq uint16, payload []byte) ([]byte, error) {
	switch {
	case src.Is4() && dst.Is4():
		icmp := make([]byte, 8+len(payload))
		icmp[0] = icmpEchoRequest
		binary.BigEndian.PutUint16(icmp[4:6], id)
		binary.BigEndian.PutUint16(icmp[6:8], seq)
		copy(icmp[8:], payload)
		binary.BigEndian.PutUint16(icmp[2:4], onesComplementSum(icmp))

		return buildIPv4(protoICMP, src, dst, icmp), nil
	case src.Is6() && dst.Is6():
		return buildICMPv6Echo(src, dst, id, seq, payload), nil
	default:
		return nil, fmt.Errorf("ICMP echo requires matching IPv4 or IPv6 addresses")
	}
}

func BuildUDP(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	switch {
	case src.Is4() && dst.Is4():
		udp := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(udp[0:2], srcPort)
		binary.BigEndian.PutUint16(udp[2:4], dstPort)
		binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
		copy(udp[8:], payload)
		// The UDP checksum is optional over IPv4 and an all-zero field marks it as
		// not computed (RFC 768).

		return buildIPv4(protoUDP, src, dst, udp), nil
	case src.Is6() && dst.Is6():
		return buildUDPv6(src, dst, srcPort, dstPort, payload), nil
	default:
		return nil, fmt.Errorf("UDP build requires matching IPv4 or IPv6 addresses")
	}
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

// InnerPacket is a decoded inner IP packet, surfaced for assertions on a
// received downlink T-PDU.
type InnerPacket struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Protocol uint8  `json:"protocol"`

	// ICMPType has no omitempty so an Echo Reply (type 0) stays distinguishable.
	ICMPType uint8  `json:"icmp_type"`
	ICMPID   uint16 `json:"icmp_id,omitempty"`
	ICMPSeq  uint16 `json:"icmp_seq,omitempty"`

	UDPSrcPort uint16 `json:"udp_src_port,omitempty"`
	UDPDstPort uint16 `json:"udp_dst_port,omitempty"`

	Payload string `json:"payload,omitempty"` // hex of the L4 payload
}

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
	case protoUDP:
		if len(l4) >= 8 {
			p.UDPSrcPort = binary.BigEndian.Uint16(l4[0:2])
			p.UDPDstPort = binary.BigEndian.Uint16(l4[2:4])
			p.Payload = hex.EncodeToString(l4[8:])
		}
	}

	return p, nil
}

func (p *InnerPacket) IsICMPEchoReply() bool {
	return (p.Protocol == protoICMP && p.ICMPType == icmpEchoReply) ||
		(p.Protocol == protoICMPv6 && p.ICMPType == icmpv6EchoReply)
}
