// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// TestEPSPathSwitchSecurityCapabilityMatch checks that when the target eNB
// reports the UE security capabilities the MME already holds, the Path Switch
// Request Acknowledge omits the UE Security Capabilities IE — there is nothing to
// correct (TS 36.413 §9.1.5.9).
func TestEPSPathSwitchSecurityCapabilityMatch(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasStep(t, enbID, ueID, "path_switch")

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestAcknowledge" {
		t.Fatalf("path switch: s1ap.message_type = %q, want PathSwitchRequestAcknowledge; body: %s", got, resp)
	}

	if got := jsonGet(resp, "s1ap.replayed_ue_security_capabilities"); got != "" {
		t.Fatalf("matching caps: Ack replayed UE security capabilities unexpectedly (%s); body: %s", got, resp)
	}
}

// TestEPSPathSwitchSecurityCapabilityMismatch checks that when the target eNB
// reports UE security capabilities that differ from the MME's stored values, the
// Path Switch Request Acknowledge replays the stored capabilities so the eNB
// corrects its context (TS 36.413 §9.1.5.9). A default UE advertised EEA0/1/2 and
// EIA0/1/2, which the S1AP encoding (dropping the EEA0/EIA0 bit) stores as
// 0xC000 for each bitmap.
func TestEPSPathSwitchSecurityCapabilityMismatch(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	// Report EEA1/EIA1 only (0x8000), which differs from the stored 0xC000.
	resp := nasBody(t, enbID, ueID, `{"message_type":"path_switch","path_switch_eea":32768,"path_switch_eia":32768}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestAcknowledge" {
		t.Fatalf("path switch: s1ap.message_type = %q, want PathSwitchRequestAcknowledge; body: %s", got, resp)
	}

	if got := jsonGet(resp, "s1ap.replayed_ue_security_capabilities"); got == "" {
		t.Fatalf("mismatched caps: MME did not replay its stored UE security capabilities (TS 36.413 §9.1.5.9); body: %s", resp)
	}

	if eea := jsonGet(resp, "s1ap.replayed_ue_security_capabilities.encryption_algorithms"); eea != "49152" {
		t.Fatalf("replayed encryption algorithms = %q, want 49152 (0xC000, the stored value); body: %s", eea, resp)
	}

	if eia := jsonGet(resp, "s1ap.replayed_ue_security_capabilities.integrity_protection_algorithms"); eia != "49152" {
		t.Fatalf("replayed integrity algorithms = %q, want 49152 (0xC000, the stored value); body: %s", eia, resp)
	}
}
