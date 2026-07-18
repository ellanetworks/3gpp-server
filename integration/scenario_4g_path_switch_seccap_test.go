// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// The UE Security Capabilities IE is optional in the acknowledge (TS 36.413 §9.1.5.9), so its presence is not asserted.
func Test4GPathSwitchSecurityCapabilityMatch(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasStep(t, enbID, ueID, "path_switch")

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestAcknowledge" {
		t.Fatalf("path switch: s1ap.message_type = %q, want PathSwitchRequestAcknowledge; body: %s", got, resp)
	}
}

func Test4GPathSwitchSecurityCapabilityMismatch(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	// Report 0x8000 (EEA1/EIA1 only), which mismatches the stored caps.
	resp := nasBody(t, enbID, ueID, `{"message_type":"path_switch","path_switch_eea":32768,"path_switch_eia":32768}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestAcknowledge" {
		t.Fatalf("path switch: s1ap.message_type = %q, want PathSwitchRequestAcknowledge; body: %s", got, resp)
	}

	if got := jsonGet(resp, "s1ap.replayed_ue_security_capabilities"); got == "" {
		t.Fatalf("mismatched caps: MME did not replay its stored UE security capabilities (TS 33.401 §7.2.4.2.2); body: %s", resp)
	}

	if eea := jsonGet(resp, "s1ap.replayed_ue_security_capabilities.encryption_algorithms"); eea != storedUESecurityCapabilities {
		t.Fatalf("replayed encryption algorithms = %q, want %s (the stored value); body: %s", eea, storedUESecurityCapabilities, resp)
	}

	if eia := jsonGet(resp, "s1ap.replayed_ue_security_capabilities.integrity_protection_algorithms"); eia != storedUESecurityCapabilities {
		t.Fatalf("replayed integrity algorithms = %q, want %s (the stored value); body: %s", eia, storedUESecurityCapabilities, resp)
	}
}
