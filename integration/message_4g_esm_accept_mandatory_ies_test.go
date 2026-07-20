// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// The Activate Default EPS Bearer Context Request piggybacked on the Attach Accept
// carries EPS QoS, Access Point Name and PDN address as mandatory IEs (TS 24.301 Table 8.3.6.1).
func Test4GESMAcceptMandatoryIEs(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	nasStep(t, enbID, ueID, "attach_request")
	nasStep(t, enbID, ueID, "authentication_response")
	accept := nasStep(t, enbID, ueID, "security_mode_complete")

	if got := jsonGet(accept, "nas.message_type"); got != "attach_accept" {
		t.Fatalf("nas.message_type = %q, want attach_accept; body: %s", got, accept)
	}

	if got := jsonGet(accept, "nas.apn"); got == "" {
		t.Errorf("Activate Default EPS Bearer Context Request missing mandatory Access Point Name (TS 24.301 Table 8.3.6.1, §9.9.4.1); body: %s", accept)
	}

	if got := jsonGet(accept, "nas.pdn_address"); got == "" {
		t.Errorf("Activate Default EPS Bearer Context Request missing mandatory PDN address (TS 24.301 Table 8.3.6.1, §9.9.4.9); body: %s", accept)
	}

	if got := jsonGet(accept, "nas.eps_qos.qci"); got == "" || got == "0" {
		t.Errorf("Activate Default EPS Bearer Context Request EPS QoS QCI = %q, want a non-zero mandatory value (TS 24.301 Table 8.3.6.1, §9.9.4.3); body: %s", got, accept)
	}

	nasStep(t, enbID, ueID, "attach_complete")
}
