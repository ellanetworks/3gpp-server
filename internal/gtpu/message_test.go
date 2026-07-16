// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package gtpu

import (
	"encoding/hex"
	"testing"
)

func mustDecode(t *testing.T, s string) *Message {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}

	m, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	return m
}

func TestDecodeErrorIndicationIEs(t *testing.T) {
	// TEID Data I = 0xFFFFFFFE, GTP-U Peer Address = 10.3.0.2.
	m := mustDecode(t, "321a001000000000"+"00000000"+"10fffffffe"+"8500040a030002")

	if m.Type != MsgErrorIndication {
		t.Fatalf("Type = %d, want %d", m.Type, MsgErrorIndication)
	}

	if m.TEIDDataI == nil || *m.TEIDDataI != 0xFFFFFFFE {
		t.Errorf("TEIDDataI = %v, want 0xFFFFFFFE", m.TEIDDataI)
	}

	if m.PeerAddress != "10.3.0.2" {
		t.Errorf("PeerAddress = %q, want 10.3.0.2", m.PeerAddress)
	}
}

func TestDecodeErrorIndicationIPv6PeerAddress(t *testing.T) {
	m := mustDecode(t, "321a001c000000000000000010fffffffe850010fd000003000000000000000000000002")

	if m.PeerAddress != "fd00:3::2" {
		t.Errorf("PeerAddress = %q, want fd00:3::2", m.PeerAddress)
	}
}

func TestDecodeEchoResponseRecovery(t *testing.T) {
	m := mustDecode(t, "3202000600000000"+"00000000"+"0e00")

	if m.Type != MsgEchoResponse {
		t.Fatalf("Type = %d, want %d", m.Type, MsgEchoResponse)
	}

	if m.Recovery == nil || *m.Recovery != 0 {
		t.Errorf("Recovery = %v, want 0", m.Recovery)
	}
}

func TestDecodeEchoResponseWithoutRecovery(t *testing.T) {
	m := mustDecode(t, "320200040000000000000000")

	if m.Recovery != nil {
		t.Errorf("Recovery = %v, want nil", m.Recovery)
	}
}

func TestDecodeDLPDUSessionInformation(t *testing.T) {
	// PDU Type 0, RQI set, QFI 9, over a 1-byte payload.
	m := mustDecode(t, "34ff00090000002a"+"00000085"+"01004900"+"aa")

	if m.PDUSession == nil {
		t.Fatal("PDUSession = nil, want a decoded container")
	}

	if m.PDUSession.PDUType != pduTypeDL {
		t.Errorf("PDUType = %d, want %d", m.PDUSession.PDUType, pduTypeDL)
	}

	if m.PDUSession.QFI != 9 {
		t.Errorf("QFI = %d, want 9", m.PDUSession.QFI)
	}

	if m.PDUSession.RQI == nil || !*m.PDUSession.RQI {
		t.Errorf("RQI = %v, want true", m.PDUSession.RQI)
	}

	if hex.EncodeToString(m.Payload) != "aa" {
		t.Errorf("Payload = %x, want aa", m.Payload)
	}
}

// TS 38.415 §5.5.3.4: the RQI is used only in the downlink direction.
func TestDecodeULPDUSessionInformationHasNoRQI(t *testing.T) {
	m, err := Decode(EncodeGPDUWithQFI(1, 5, []byte{0xaa}))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if m.PDUSession == nil {
		t.Fatal("PDUSession = nil, want a decoded container")
	}

	if m.PDUSession.PDUType != pduTypeUL {
		t.Errorf("PDUType = %d, want %d", m.PDUSession.PDUType, pduTypeUL)
	}

	if m.PDUSession.QFI != 5 {
		t.Errorf("QFI = %d, want 5", m.PDUSession.QFI)
	}

	if m.PDUSession.RQI != nil {
		t.Errorf("RQI = %v, want nil", m.PDUSession.RQI)
	}
}

func TestDecodeGPDUWithoutExtensionHeaders(t *testing.T) {
	m, err := Decode(EncodeGPDU(7, []byte{0xaa, 0xbb}))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if m.PDUSession != nil {
		t.Errorf("PDUSession = %+v, want nil", m.PDUSession)
	}

	if m.TEID != 7 {
		t.Errorf("TEID = %d, want 7", m.TEID)
	}
}

func TestDecodeTruncatedIEsAreIgnored(t *testing.T) {
	for name, fixture := range map[string]string{
		"truncated TV":       "321a00070000000000000000" + "10ffff",
		"truncated TLV":      "321a00090000000000000000" + "8500040a03",
		"unknown TV stops":   "321a000a0000000000000000" + "0f" + "10fffffffe",
		"length beyond edge": "321a00060000000000000000" + "85ff",
	} {
		t.Run(name, func(t *testing.T) {
			b, err := hex.DecodeString(fixture)
			if err != nil {
				t.Fatalf("bad fixture: %v", err)
			}

			if _, err := Decode(b); err != nil {
				t.Fatalf("Decode: %v", err)
			}
		})
	}
}
