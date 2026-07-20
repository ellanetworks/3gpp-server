// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// A replayed mobility Registration Request carrying a stale NAS COUNT fails the
// integrity check (TS 24.501 §4.4.3.5), so the AMF must not accept it.
func Test5GRegistration_MobilityReplay(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)

	registerThenIdle(t, gnbID, ueID)

	body := fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d}`, registrationTypeMobility)
	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
	if status != 200 {
		t.Fatalf("first mobility registration: HTTP %d, want 200\n  body: %s", status, resp)
	}
	if got := jsonGet(resp, "nas.message_type"); got != nasRegistrationAccept {
		t.Fatalf("first mobility registration: nas.message_type = %q, want registration_accept\n  body: %s", got, resp)
	}

	replay := fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d,"nas_count":0,"timeout_ms":3000}`, registrationTypeMobility)
	status, resp = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", replay)
	if status != 200 && status != 504 {
		t.Fatalf("mobility replay: HTTP %d, want 200 or 504\n  body: %s", status, resp)
	}
	if got := jsonGet(resp, "nas.message_type"); got == nasRegistrationAccept {
		t.Fatalf("the AMF accepted a replayed mobility Registration Request with a stale NAS COUNT (TS 24.501 §4.4.3.5)\n  body: %s", resp)
	}

	assertGNBCoreAlive(t)
}
