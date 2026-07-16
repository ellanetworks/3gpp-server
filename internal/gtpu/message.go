// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

// Package gtpu implements GTP-U (TS 29.281) encode/decode and an N3 endpoint.
package gtpu

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	MsgEchoRequest     = 1
	MsgEchoResponse    = 2
	MsgErrorIndication = 26
	MsgGPDU            = 255
)

const (
	flagsGPDU    = 0x30
	flagsWithSeq = 0x32
	flagsWithExt = 0x34

	extPDUSessionContainer = 0x85

	pduTypeDL = 0
	pduTypeUL = 1

	port = 2152
)

// TS 29.281 Table 8.1-1
const (
	ieRecovery    = 14
	ieTEIDDataI   = 16
	iePeerAddress = 133
)

var tvValueLengths = map[uint8]int{ieRecovery: 1, ieTEIDDataI: 4}

const Port = port

// TS 38.415 §5.5.2
type PDUSessionContainer struct {
	PDUType uint8 `json:"pdu_type"`
	QFI     uint8 `json:"qfi"`
	RQI     *bool `json:"rqi,omitempty"`
}

type Message struct {
	Type    uint8
	TEID    uint32
	Seq     uint16
	HasSeq  bool
	Payload []byte

	PDUSession *PDUSessionContainer

	Recovery    *uint8
	TEIDDataI   *uint32
	PeerAddress string
}

func EncodeGPDU(teid uint32, tpdu []byte) []byte {
	out := make([]byte, 8+len(tpdu))
	out[0] = flagsGPDU
	out[1] = MsgGPDU
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)-8))
	binary.BigEndian.PutUint32(out[4:8], teid)
	copy(out[8:], tpdu)

	return out
}

// The uplink PDU Session Container (TS 38.415) is what a 5G UPF expects on N3.
func EncodeGPDUWithQFI(teid uint32, qfi uint8, tpdu []byte) []byte {
	out := make([]byte, 16+len(tpdu))
	out[0] = flagsWithExt
	out[1] = MsgGPDU
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)-8))
	binary.BigEndian.PutUint32(out[4:8], teid)
	out[11] = extPDUSessionContainer
	out[12] = 0x01
	out[13] = pduTypeUL << 4
	out[14] = qfi & 0x3f
	out[15] = 0x00
	copy(out[16:], tpdu)

	return out
}

func EncodeEchoRequest(seq uint16) []byte {
	out := make([]byte, 12)
	out[0] = flagsWithSeq
	out[1] = MsgEchoRequest
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)-8))
	binary.BigEndian.PutUint16(out[8:10], seq)

	return out
}

// TS 29.281 §5.1
func Decode(b []byte) (*Message, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("gtp-u message too short: %d bytes", len(b))
	}

	flags := b[0]
	if flags>>5 != 1 {
		return nil, fmt.Errorf("unsupported GTP version: %d", flags>>5)
	}

	m := &Message{
		Type: b[1],
		TEID: binary.BigEndian.Uint32(b[4:8]),
	}

	length := int(binary.BigEndian.Uint16(b[2:4]))

	payloadStart := 8

	optional := flags&0x07 != 0
	if optional {
		if len(b) < 12 {
			return nil, fmt.Errorf("gtp-u message with flags but truncated: %d bytes", len(b))
		}

		if flags&0x02 != 0 {
			m.Seq = binary.BigEndian.Uint16(b[8:10])
			m.HasSeq = true
		}

		nextExt := b[11]
		payloadStart = 12

		for nextExt != 0 {
			if payloadStart >= len(b) {
				break
			}

			extLen := int(b[payloadStart]) * 4
			if extLen == 0 || payloadStart+extLen > len(b) {
				break
			}

			if nextExt == extPDUSessionContainer {
				m.PDUSession = decodePDUSessionContainer(b[payloadStart+1 : payloadStart+extLen-1])
			}

			nextExt = b[payloadStart+extLen-1]
			payloadStart += extLen
		}
	}

	end := 8 + length
	if end > len(b) {
		end = len(b)
	}

	if payloadStart > end {
		payloadStart = end
	}

	m.Payload = b[payloadStart:end]

	if m.Type != MsgGPDU {
		m.decodeIEs(m.Payload)
	}

	return m, nil
}

// TS 38.415 §5.5.2.1, §5.5.2.2
func decodePDUSessionContainer(b []byte) *PDUSessionContainer {
	if len(b) < 2 {
		return nil
	}

	c := &PDUSessionContainer{
		PDUType: b[0] >> 4,
		QFI:     b[1] & 0x3f,
	}

	// TS 38.415 §5.5.3.4: the RQI is used only in the downlink direction.
	if c.PDUType == pduTypeDL {
		rqi := b[1]&0x40 != 0
		c.RQI = &rqi
	}

	return c
}

// TS 29.281 §8.1: type bit 8 clear selects TV, set selects TLV with a 2-octet length.
func (m *Message) decodeIEs(b []byte) {
	for i := 0; i < len(b); {
		ieType := b[i]

		if ieType&0x80 == 0 {
			n, known := tvValueLengths[ieType]
			if !known || i+1+n > len(b) {
				return
			}

			m.setIE(ieType, b[i+1:i+1+n])
			i += 1 + n

			continue
		}

		if i+3 > len(b) {
			return
		}

		n := int(binary.BigEndian.Uint16(b[i+1 : i+3]))
		if i+3+n > len(b) {
			return
		}

		m.setIE(ieType, b[i+3:i+3+n])
		i += 3 + n
	}
}

func (m *Message) setIE(ieType uint8, value []byte) {
	switch ieType {
	case ieRecovery:
		restartCounter := value[0]
		m.Recovery = &restartCounter

	case ieTEIDDataI:
		teid := binary.BigEndian.Uint32(value)
		m.TEIDDataI = &teid

	case iePeerAddress:
		// TS 29.281 §8.4: the length field admits only 4 (IPv4) or 16 (IPv6).
		if addr, ok := netip.AddrFromSlice(value); ok {
			m.PeerAddress = addr.Unmap().String()
		}
	}
}
