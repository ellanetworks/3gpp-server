// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"bytes"
	"testing"
)

func TestEncodePLMN(t *testing.T) {
	valid := []struct {
		mcc, mnc string
		want     []byte
	}{
		{"001", "01", []byte{0x00, 0xf1, 0x10}},
		{"123", "45", []byte{0x21, 0xf3, 0x54}},
		{"123", "456", []byte{0x21, 0x63, 0x54}},
		{"310", "260", []byte{0x13, 0x00, 0x62}},
	}

	for _, tc := range valid {
		got, err := encodePLMN(tc.mcc, tc.mnc)
		if err != nil {
			t.Errorf("encodePLMN(%q,%q) unexpected error: %v", tc.mcc, tc.mnc, err)
			continue
		}

		if !bytes.Equal(got, tc.want) {
			t.Errorf("encodePLMN(%q,%q) = % x, want % x", tc.mcc, tc.mnc, got, tc.want)
		}
	}

	// Malformed input must return an error, never panic (short MCC/MNC once caused
	// an index-out-of-range panic reachable from HTTP input).
	invalid := []struct {
		name, mcc, mnc string
	}{
		{"short mcc", "1", "01"},
		{"two-digit mcc", "12", "01"},
		{"empty mcc", "", "01"},
		{"long mcc", "1234", "01"},
		{"short mnc", "001", "1"},
		{"empty mnc", "001", ""},
		{"long mnc", "001", "4567"},
		{"non-digit mcc", "12a", "01"},
		{"non-digit mnc", "001", "4a"},
	}

	for _, tc := range invalid {
		if _, err := encodePLMN(tc.mcc, tc.mnc); err == nil {
			t.Errorf("%s: encodePLMN(%q,%q) = nil error, want error", tc.name, tc.mcc, tc.mnc)
		}
	}
}
