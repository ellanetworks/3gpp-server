// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"strings"
	"testing"
)

// TS 24.501 §8.2.11: a DL NAS TRANSPORT is EPD, security header type, message
// type, payload container type, then the payload container (2-octet length +
// contents). With payload container type N1 SM information the contents are a
// 5GSM message (§9.11.3.40); a message-type octet of 0xff is undefined, so the
// inner decode must fail and Decode must surface that failure.
func TestDecodeDLNASTransportMalformedInnerPayloadErrors(t *testing.T) {
	msg := []byte{
		0x7e,       // extended protocol discriminator: 5GMM
		0x00,       // spare half octet + security header type: plain
		0x68,       // message type: DL NAS transport
		0x01,       // spare half octet + payload container type: N1 SM information
		0x00, 0x04, // payload container length: 4
		0x2e, 0x00, 0x00, 0xff, // inner 5GSM header with undefined message type 0xff
	}

	resp, err := Decode(msg)
	if err == nil {
		t.Fatalf("expected error for malformed inner 5GSM payload, got resp=%+v", resp)
	}
}

// TS 24.501 §9.7: the message-type octet of a 5GSM message is its fourth octet.
// A plain top-level 5GSM STATUS (message type 0xd6) is not a 5GMM message the
// dispatch covers; its numeric type must be preserved in the decoded result.
func TestDecodeUnknownMessagePreservesNumericType(t *testing.T) {
	msg := []byte{
		0x2e, // extended protocol discriminator: 5GSM
		0x00, // PDU session identity
		0x00, // procedure transaction identity
		0xd6, // message type: 5GSM STATUS
		0x24, // 5GSM cause
	}

	resp, err := Decode(msg)
	if err != nil {
		t.Fatalf("expected successful decode, got error: %v", err)
	}

	if resp.MessageType == "unknown" {
		t.Fatalf("message type discards the numeric 5GS message type: %q", resp.MessageType)
	}

	if !strings.Contains(resp.MessageType, "d6") {
		t.Fatalf("expected message type to preserve 0xd6, got %q", resp.MessageType)
	}
}
