// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"encoding/hex"
	"testing"

	"github.com/ellanetworks/core/s1ap"
	"github.com/ellanetworks/core/s1ap/aper"
)

// maxProtocolIEs bounds a ProtocolIE-Container's field count (TS 36.413,
// S1AP-Constants).
const maxProtocolIEs = 65535

// criticalityRootCount is the size of the Criticality ENUMERATED root
// (TS 36.413 §10.3.2): reject, ignore, notify.
const criticalityRootCount = 3

type protocolIEField struct {
	id    int64
	crit  int
	value []byte
}

// appendIE re-encodes a message body's ProtocolIE-Container with one extra
// ProtocolIE-Field appended, the wire form of an MME sending an IE the message
// type does not model.
func appendIE(t *testing.T, body []byte, id int64, crit s1ap.Criticality, value []byte) []byte {
	t.Helper()

	r := aper.NewReader(body)

	extPresent, _, err := r.ReadSequencePreamble(true, 0)
	if err != nil {
		t.Fatalf("read body preamble: %v", err)
	}

	if extPresent {
		t.Fatal("body preamble extension bit = true, want false")
	}

	n, err := r.ReadConstrainedLength(0, maxProtocolIEs)
	if err != nil {
		t.Fatalf("read IE count: %v", err)
	}

	fields := make([]protocolIEField, 0, n+1)

	for i := 0; i < n; i++ {
		var f protocolIEField

		if f.id, err = r.ReadConstrainedInt(0, maxProtocolIEs); err != nil {
			t.Fatalf("read IE %d id: %v", i, err)
		}

		if f.crit, _, err = r.ReadEnum(criticalityRootCount, false); err != nil {
			t.Fatalf("read IE %d criticality: %v", i, err)
		}

		if f.value, err = r.ReadOpenType(); err != nil {
			t.Fatalf("read IE %d value: %v", i, err)
		}

		fields = append(fields, f)
	}

	fields = append(fields, protocolIEField{id: id, crit: int(crit), value: value})

	var w aper.Writer

	w.WriteSequencePreamble(true, false, nil)

	if err := w.WriteConstrainedLength(len(fields), 0, maxProtocolIEs); err != nil {
		t.Fatalf("write IE count: %v", err)
	}

	for _, f := range fields {
		if err := w.WriteConstrainedInt(f.id, 0, maxProtocolIEs); err != nil {
			t.Fatalf("write IE %d id: %v", f.id, err)
		}

		if err := w.WriteEnum(f.crit, criticalityRootCount, false, false); err != nil {
			t.Fatalf("write IE %d criticality: %v", f.id, err)
		}

		if err := w.WriteOpenType(f.value); err != nil {
			t.Fatalf("write IE %d value: %v", f.id, err)
		}
	}

	return w.Bytes()
}

func handoverCancelAcknowledgeWithIE(t *testing.T, id int64, crit s1ap.Criticality, value []byte) []byte {
	t.Helper()

	ack := &s1ap.HandoverCancelAcknowledge{MMEUES1APID: 1, ENBUES1APID: 2}

	encoded, err := ack.Marshal()
	if err != nil {
		t.Fatalf("marshal HandoverCancelAcknowledge: %v", err)
	}

	pdu, err := s1ap.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("unmarshal HandoverCancelAcknowledge: %v", err)
	}

	so, ok := pdu.(*s1ap.SuccessfulOutcome)
	if !ok {
		t.Fatalf("PDU = %T, want *s1ap.SuccessfulOutcome", pdu)
	}

	so.Value = appendIE(t, so.Value, id, crit, value)

	tampered, err := s1ap.Marshal(so)
	if err != nil {
		t.Fatalf("marshal tampered PDU: %v", err)
	}

	return tampered
}

// TestDecodeSurfacesUnmodeledIEWithCriticality checks an IE the message type does
// not model reaches the JSON with the criticality received on the wire. TS 36.413
// §10.3.2 makes that criticality the sole input to a receiver's handling of a
// not-comprehended IE (§10.3.4.2), so an IE reported without it cannot be judged.
func TestDecodeSurfacesUnmodeledIEWithCriticality(t *testing.T) {
	const unmodeledIEID = 300 // no HANDOVER CANCEL ACKNOWLEDGE IE bears this id

	value := []byte{0xde, 0xad, 0xbe, 0xef}

	resp, err := Decode(handoverCancelAcknowledgeWithIE(t, unmodeledIEID, s1ap.CriticalityNotify, value))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if len(resp.UnknownIEs) != 1 {
		t.Fatalf("unknown_ies = %+v, want 1 entry", resp.UnknownIEs)
	}

	got := resp.UnknownIEs[0]
	want := UnknownIEJSON{ID: unmodeledIEID, Criticality: "notify", ValueHex: hex.EncodeToString(value)}

	if got != want {
		t.Fatalf("unknown_ies[0] = %+v, want %+v", got, want)
	}
}

// TestDecodeReportsUnmodeledIECriticalityReject checks a not-comprehended IE
// marked "reject" is distinguishable from one marked "notify": TS 36.413
// §10.3.4.2 requires the receiver to reject the procedure in the first case and
// to continue it in the second.
func TestDecodeReportsUnmodeledIECriticalityReject(t *testing.T) {
	const unmodeledIEID = 301

	resp, err := Decode(handoverCancelAcknowledgeWithIE(t, unmodeledIEID, s1ap.CriticalityReject, nil))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if len(resp.UnknownIEs) != 1 {
		t.Fatalf("unknown_ies = %+v, want 1 entry", resp.UnknownIEs)
	}

	if resp.UnknownIEs[0].Criticality != "reject" {
		t.Fatalf("unknown_ies[0].criticality = %q, want %q", resp.UnknownIEs[0].Criticality, "reject")
	}
}

func TestDecodeOmitsUnknownIEsWhenAllModeled(t *testing.T) {
	ack := &s1ap.HandoverCancelAcknowledge{MMEUES1APID: 1, ENBUES1APID: 2}

	encoded, err := ack.Marshal()
	if err != nil {
		t.Fatalf("marshal HandoverCancelAcknowledge: %v", err)
	}

	resp, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if len(resp.UnknownIEs) != 0 {
		t.Fatalf("unknown_ies = %+v, want none", resp.UnknownIEs)
	}
}
