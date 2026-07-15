// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

// Package gtpu implements GTP-U (TS 29.281) encode/decode and an N3 endpoint.
package gtpu

import (
	"encoding/binary"
	"fmt"
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
	pscPDUTypeUL           = 0x10

	port = 2152
)

const Port = port

type Message struct {
	Type    uint8
	TEID    uint32
	Seq     uint16
	HasSeq  bool
	Payload []byte
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
	out[13] = pscPDUTypeUL
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

	return m, nil
}
