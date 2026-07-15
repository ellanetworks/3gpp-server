// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import "testing"

// plainSecurityModeCommand is a SECURITY MODE COMMAND sent with security header
// type "plain" (TS 24.501 §8.2.25): EPD, security header type, message type,
// Selected NAS security algorithms (§9.11.3.34: ciphering in bits 8-5, integrity
// in bits 4-1), ngKSI, then the Replayed UE security capabilities (LV).
func plainSecurityModeCommand() []byte {
	return []byte{
		0x7e,             // extended protocol discriminator: 5GMM
		0x00,             // spare half octet + security header type: plain
		0x5d,             // message type: SECURITY MODE COMMAND
		0x22,             // selected NAS security algorithms: ciphering NEA2, integrity NIA2
		0x00,             // spare half octet + ngKSI: 0
		0x02, 0xe0, 0xe0, // replayed UE security capabilities (LV, length 2)
	}
}

// TestDecodeSurfacesIEsOfAnUnprotectedSecurityModeCommand checks the plain path
// surfaces a SECURITY MODE COMMAND's IEs.
//
// TS 24.501 §4.4.4.2 requires the AMF to send this message integrity protected
// (with a new 5G NAS security context, §5.4.2.2), so an unprotected one is a
// deviation. Catching it needs the message's own IEs — the selected algorithms —
// which the plain path must therefore decode, exactly as the secured path does.
func TestDecodeSurfacesIEsOfAnUnprotectedSecurityModeCommand(t *testing.T) {
	resp, err := Decode(plainSecurityModeCommand())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.SecurityHeaderType != "plain" {
		t.Fatalf("security_header_type = %q, want plain", resp.SecurityHeaderType)
	}

	if resp.MessageType != "security_mode_command" {
		t.Fatalf("message_type = %q, want security_mode_command", resp.MessageType)
	}

	if resp.SelectedCipheringAlg == nil || *resp.SelectedCipheringAlg != 2 {
		t.Errorf("selected ciphering algorithm = %v, want 2 (NEA2) — an unprotected Security Mode Command must still surface its selected algorithms (TS 24.501 §9.11.3.34)", resp.SelectedCipheringAlg)
	}

	if resp.SelectedIntegrityAlg == nil || *resp.SelectedIntegrityAlg != 2 {
		t.Errorf("selected integrity algorithm = %v, want 2 (NIA2) — an unprotected Security Mode Command must still surface its selected algorithms (TS 24.501 §9.11.3.34)", resp.SelectedIntegrityAlg)
	}

	if resp.NgKSI == nil || *resp.NgKSI != 0 {
		t.Errorf("ngKSI = %v, want 0 (TS 24.501 §9.11.3.32)", resp.NgKSI)
	}
}
