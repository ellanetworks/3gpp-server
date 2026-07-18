// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import "testing"

func TestDecodeRejectsMalformedPDUs(t *testing.T) {
	tests := []struct {
		name string
		pdu  []byte
	}{
		{"empty", nil},
		{"header only", []byte{0x07}},
		{"non-eps protocol discriminator", []byte{0x01, 0x00}},
		{"truncated authentication request", []byte{0x07, 0x52}},
		{"truncated esm header", []byte{0x02}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(tt.pdu); err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}
