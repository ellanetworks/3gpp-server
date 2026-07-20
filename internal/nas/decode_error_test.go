// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"strings"
	"testing"
)

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
