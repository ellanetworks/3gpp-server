// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"strings"
	"testing"
)

// TS 24.501 §5.4.2.2: the SECURITY MODE COMMAND carries the replayed UE security
// capabilities (for bidding-down detection), the selected 5GS ciphering and
// integrity algorithms, and the ngKSI. The default UE advertises {0xE0,0xE0}.
func Test5GSecurityModeAlgorithmSelection(t *testing.T) {
	const advertised = "e0e0"

	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)

	if got := jsonGet(ngap5GStep(t, gnbID, ueID, "registration_request"), "nas.message_type"); got != nasAuthenticationRequest {
		t.Fatalf("registration_request: nas.message_type = %q, want authentication_request", got)
	}

	smc := ngap5GStep(t, gnbID, ueID, "authentication_response")
	if got := jsonGet(smc, "nas.message_type"); got != nasSecurityModeCommand {
		t.Fatalf("authentication_response: nas.message_type = %q, want security_mode_command; body: %s", got, smc)
	}

	if got := jsonGet(smc, "nas.replayed_ue_security_capabilities"); !strings.HasPrefix(got, advertised) {
		t.Fatalf("replayed UE security capabilities = %q, want the advertised %q replayed (bidding-down, TS 24.501 §5.4.2.2); body: %s", got, advertised, smc)
	}

	if got := jsonGet(smc, "mac_verified"); got != "true" {
		t.Fatalf("Security Mode Command NAS-MAC did not verify; body: %s", smc)
	}

	if got := jsonGet(smc, "nas.selected_ciphering_algorithm"); got == "" {
		t.Errorf("Security Mode Command missing the selected 5GS ciphering algorithm (TS 24.501 §5.4.2.2); body: %s", smc)
	}

	if got := jsonGet(smc, "nas.selected_integrity_algorithm"); got == "" {
		t.Errorf("Security Mode Command missing the selected 5GS integrity algorithm (TS 24.501 §5.4.2.2); body: %s", smc)
	}

	if got := jsonGet(smc, "nas.ng_ksi"); got == "" {
		t.Errorf("Security Mode Command missing the ngKSI (TS 24.501 §5.4.2.2); body: %s", smc)
	}
}
