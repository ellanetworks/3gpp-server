// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas5gs

import "testing"

// TS 24.501 Table 8.3.14.1.1: EPD, PDU session ID, PTI, message identity, 5GSM cause.
func releaseCommandMandatoryPart() []byte {
	return []byte{0x2e, 0x01, 0x07, 0xd1, 0x24}
}

func TestReleaseCommandAccessTypeDetection(t *testing.T) {
	tests := []struct {
		name     string
		optional []byte
		want     bool
	}{
		{
			name: "mandatory part only",
		},
		{
			name:     "access type IE alone",
			optional: []byte{0xd1},
			want:     true,
		},
		{
			name:     "access type IE after a back-off timer",
			optional: []byte{0x37, 0x01, 0x0a, 0xd1},
			want:     true,
		},
		{
			// 0xd1 inside the EPCO contents must not read as an Access type IEI.
			name:     "extended protocol configuration options containing the access type IEI",
			optional: []byte{0x7b, 0x00, 0x03, 0xd1, 0xd1, 0xd1},
		},
		{
			name:     "access type IE after extended protocol configuration options",
			optional: []byte{0x7b, 0x00, 0x02, 0x00, 0x00, 0xd1},
			want:     true,
		},
		{
			name:     "truncated length-value IE",
			optional: []byte{0x37, 0x05, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := append(releaseCommandMandatoryPart(), tt.optional...)

			if got := releaseCommandHasAccessType(raw); got != tt.want {
				t.Errorf("releaseCommandHasAccessType = %v, want %v", got, tt.want)
			}
		})
	}
}
