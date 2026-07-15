// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func createENBUEWithIMSI(t *testing.T, enbID, imsi string) string {
	t.Helper()

	body := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000000"}`, imsi, testK, testOPc)

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create ue: HTTP %d: %s", status, resp)
	}

	return jsonGet(resp, "ue_id")
}

// Test4GAttachUnknownIMSI checks an attach from an IMSI the MME cannot serve
// draws an Attach Reject with EMM cause #2 "IMSI unknown in HSS"
// (TS 24.301 §5.5.1.2.5).
func Test4GAttachUnknownIMSI(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := createENBUEWithIMSI(t, enbID, "001019999999999")

	resp := nasStep(t, enbID, ueID, "attach_request")

	if got := jsonGet(resp, "nas.message_type"); got != "attach_reject" {
		t.Fatalf("nas.message_type = %q, want attach_reject; body: %s", got, resp)
	}

	if got := jsonGet(resp, "nas.emm_cause"); got != "2" {
		t.Fatalf("attach_reject emm_cause = %q, want 2 (IMSI unknown in HSS); body: %s", got, resp)
	}
}

// Test4GCombinedAttach checks a combined EPS/IMSI attach succeeds but reports
// EPS-only service via EMM cause #18 "CS domain not available", since the MME has
// no SGs interface (TS 24.301 §5.5.1.2.4).
func Test4GCombinedAttach(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	if got := jsonGet(nasBody(t, enbID, ueID, `{"message_type":"attach_request","attach_type":2}`), "nas.message_type"); got != "authentication_request" {
		t.Fatalf("combined attach_request: got %q", got)
	}

	nasStep(t, enbID, ueID, "authentication_response")
	accept := nasStep(t, enbID, ueID, "security_mode_complete")

	if got := jsonGet(accept, "nas.message_type"); got != "attach_accept" {
		t.Fatalf("nas.message_type = %q, want attach_accept; body: %s", got, accept)
	}

	if got := jsonGet(accept, "nas.emm_cause"); got != "18" {
		t.Fatalf("combined-attach Attach Accept emm_cause = %q, want 18 (CS domain not available); body: %s", got, accept)
	}
}
