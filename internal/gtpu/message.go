// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

// Package gtpu implements the minimal GTP-U (TS 29.281) encode/decode and an
// N3 endpoint so the emulated gNB can terminate the user-plane tunnel: send
// uplink G-PDUs to the UPF, receive downlink G-PDUs, and exchange path-
// management messages (Echo, Error Indication).
package gtpu

import (
	"encoding/binary"
	"fmt"
)

// GTP-U message types (TS 29.281 §7.1, table 6.1-1).
const (
	MsgEchoRequest     = 1
	MsgEchoResponse    = 2
	MsgErrorIndication = 26
	MsgGPDU            = 255
)

const (
	// Version 1, Protocol Type GTP (1), no extension/sequence/N-PDU flags.
	flagsGPDU = 0x30
	// Same flags with the sequence-number flag set (S=1).
	flagsWithSeq = 0x32
	// Same flags with the extension-header flag set (E=1).
	flagsWithExt = 0x34

	extPDUSessionContainer = 0x85 // next-extension-header type (TS 29.281)
	pscPDUTypeUL           = 0x10 // PDU Type 1 (UL PDU Session Information) in the high nibble

	port = 2152
)

const Port = port

type Message struct {
	Type    uint8
	TEID    uint32
	Seq     uint16
	HasSeq  bool
	Payload []byte // T-PDU for a G-PDU; IE bytes for path-management messages
}

func EncodeGPDU(teid uint32, tpdu []byte) []byte {
	out := make([]byte, 8+len(tpdu))
	out[0] = flagsGPDU
	out[1] = MsgGPDU
	binary.BigEndian.PutUint16(out[2:4], uint16(len(tpdu)))
	binary.BigEndian.PutUint32(out[4:8], teid)
	copy(out[8:], tpdu)

	return out
}

// EncodeGPDUWithQFI wraps an inner IP packet in a G-PDU carrying the uplink PDU
// Session Container extension header (TS 38.415) with the QFI — the form an
// NG-RAN node sends uplink user data, and what a 5G UPF expects on N3.
func EncodeGPDUWithQFI(teid uint32, qfi uint8, tpdu []byte) []byte {
	out := make([]byte, 16+len(tpdu))
	out[0] = flagsWithExt
	out[1] = MsgGPDU
	binary.BigEndian.PutUint16(out[2:4], uint16(8+len(tpdu))) // 4-octet optional block + 4-octet PSC ext + T-PDU
	binary.BigEndian.PutUint32(out[4:8], teid)
	// out[8:11] are sequence + N-PDU (zero); out[11] is the next-extension type.
	out[11] = extPDUSessionContainer
	// PDU Session Container extension header (4 octets): length, content, next.
	out[12] = 0x01 // length in 4-octet units
	out[13] = pscPDUTypeUL
	out[14] = qfi & 0x3f
	out[15] = 0x00 // no further extension header
	copy(out[16:], tpdu)

	return out
}

// EncodeEchoRequest builds a GTP-U Echo Request (TEID 0) with a sequence number
// (TS 29.281 §7.2.1: Echo messages set the S flag).
func EncodeEchoRequest(seq uint16) []byte {
	out := make([]byte, 12)
	out[0] = flagsWithSeq
	out[1] = MsgEchoRequest
	binary.BigEndian.PutUint16(out[2:4], 4) // length: TEID-trailing octets (seq + npdu + next-ext)
	// TEID is 0 for path management.
	binary.BigEndian.PutUint16(out[8:10], seq)

	return out
}

// Decode parses a GTP-U message header (TS 29.281 §5.1).
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

	// An optional 4-octet block (sequence number, N-PDU number, next-extension
	// header type) is present when any of the S/PN/E flags are set.
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

		// Walk extension headers: each is length (4-octet units), content, and a
		// next-extension-header type. The chain ends at type 0.
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

	// length counts the octets after the first 8 (mandatory) header bytes.
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
