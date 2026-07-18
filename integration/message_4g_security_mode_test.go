// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func attachToSMC(t *testing.T, enbID, ueNetworkCapability string) (string, []byte) {
	t.Helper()

	capField := ""
	if ueNetworkCapability != "" {
		capField = fmt.Sprintf(`,"ue_network_capability":%q`, ueNetworkCapability)
	}

	body := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000000"%s}`,
		claimSubscriber(t)[len("imsi-"):], testK, testOPc, capField)

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create ue: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")

	if got := jsonGet(nasStep(t, enbID, ueID, "attach_request"), "nas.message_type"); got != "authentication_request" {
		t.Fatalf("attach_request: got %q", got)
	}

	smc := nasStep(t, enbID, ueID, "authentication_response")
	if got := jsonGet(smc, "nas.message_type"); got != "security_mode_command" {
		t.Fatalf("authentication_response: nas.message_type = %q, want security_mode_command; body: %s", got, smc)
	}

	return ueID, smc
}

func Test4GSecurityModeAlgorithmSelection(t *testing.T) {
	enbID := mustCreateENB(t)

	tests := []struct {
		name     string
		cap      string
		wantInt  []string
		wantCiph []string
	}{
		{"EEA2/EIA2 only", "2020", []string{"2"}, []string{"2"}},
		{"EEA1+2 / EIA1+2", "6060", []string{"1", "2"}, []string{"1", "2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, smc := attachToSMC(t, enbID, tt.cap)

			if got := jsonGet(smc, "nas.replayed_ue_security_capabilities"); got != tt.cap {
				t.Fatalf("replayed UE security capabilities = %q, want %q (bidding-down); body: %s", got, tt.cap, smc)
			}

			if got := jsonGet(smc, "mac_verified"); got != "true" {
				t.Fatalf("Security Mode Command NAS-MAC did not verify; body: %s", smc)
			}

			if got := jsonGet(smc, "nas.selected_integrity_algorithm"); !contains(tt.wantInt, got) {
				t.Fatalf("selected_integrity_algorithm = %q, want one of %v (from the advertised set, non-EIA0); body: %s", got, tt.wantInt, smc)
			}

			if got := jsonGet(smc, "nas.selected_ciphering_algorithm"); !contains(tt.wantCiph, got) {
				t.Fatalf("selected_ciphering_algorithm = %q, want one of %v; body: %s", got, tt.wantCiph, smc)
			}
		})
	}
}

func Test4GSecurityModeReject(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID, _ := attachToSMC(t, enbID, "")

	resp := nasStep(t, enbID, ueID, "security_mode_reject")

	if got := jsonGet(resp, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("after Security Mode Reject, s1ap.message_type = %q, want UEContextReleaseCommand (TS 24.301 §5.4.3.5); body: %s", got, resp)
	}
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}

	return false
}
