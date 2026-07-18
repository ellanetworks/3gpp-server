// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import "testing"

func TestDecodeDispatchesMessageType(t *testing.T) {
	tests := []struct {
		name string
		pdu  []byte
		want string
	}{
		{"authentication reject", []byte{0x07, 0x54}, "authentication_reject"},
		{"identity request", []byte{0x07, 0x55, 0x01}, "identity_request"},
		{"emm status", []byte{0x07, 0x60}, "emm_status"},
		{"detach request", []byte{0x07, 0x45}, "detach_request"},
		{"detach accept", []byte{0x07, 0x46}, "detach_accept"},
		{"service reject", []byte{0x07, 0x4e, 0x16}, "service_reject"},
		{"tracking area update reject", []byte{0x07, 0x4b, 0x16}, "tracking_area_update_reject"},
		{"unknown emm message", []byte{0x07, 0x50}, "emm_message_0x50"},
		{"unknown esm message", []byte{0x02, 0x00, 0x99}, "esm_message_0x99"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := Decode(tt.pdu)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			if resp.MessageType != tt.want {
				t.Fatalf("message_type = %q, want %q", resp.MessageType, tt.want)
			}
		})
	}
}

// TS 24.301 §8.2.20; octet 3 selects the ciphering (bits 8-5) and integrity (bits 4-1) algorithms, octet 4 carries the NAS key set identifier (§9.9.3.21).
func plainSecurityModeCommand() []byte {
	return []byte{
		0x07,             // security header type plain | protocol discriminator EMM
		0x5d,             // message type: SECURITY MODE COMMAND
		0x22,             // selected NAS security algorithms: ciphering EEA2, integrity EIA2
		0x07,             // spare half octet | NAS key set identifier: 7
		0x02, 0xe0, 0xe0, // replayed UE security capabilities (LV, length 2)
	}
}

func TestDecodeSurfacesSecurityModeCommandIEs(t *testing.T) {
	resp, err := Decode(plainSecurityModeCommand())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.MessageType != "security_mode_command" {
		t.Fatalf("message_type = %q, want security_mode_command", resp.MessageType)
	}

	if resp.SecurityHeaderType != "plain" {
		t.Fatalf("security_header_type = %q, want plain", resp.SecurityHeaderType)
	}

	if resp.SelectedCipheringAlgorithm == nil || *resp.SelectedCipheringAlgorithm != 2 {
		t.Errorf("selected_ciphering_algorithm = %v, want 2 (EEA2)", resp.SelectedCipheringAlgorithm)
	}

	if resp.SelectedIntegrityAlgorithm == nil || *resp.SelectedIntegrityAlgorithm != 2 {
		t.Errorf("selected_integrity_algorithm = %v, want 2 (EIA2)", resp.SelectedIntegrityAlgorithm)
	}

	if resp.NASKeySetIdentifier == nil || *resp.NASKeySetIdentifier != 7 {
		t.Errorf("nas_key_set_identifier = %v, want 7", resp.NASKeySetIdentifier)
	}
}
