// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Security Mode Reject (TS 24.501 §5.4.2.5): the UE rejects a Security Mode
// Command, and the AMF shall abort the ongoing (registration) procedure.

package integration_test

import (
	"fmt"
	"testing"
)

func securityModePending(t *testing.T) (string, string) {
	t.Helper()

	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	steps := []struct {
		body string
		want string
	}{
		{`{"message_type":"registration_request"}`, nasAuthenticationRequest},
		{`{"message_type":"authentication_response"}`, nasSecurityModeCommand},
	}
	for i, step := range steps {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", step.body)
		if status != 200 || jsonGet(body, "nas.message_type") != step.want {
			t.Fatalf("step %d: HTTP %d nas=%q want %q\n  body: %s", i, status, jsonGet(body, "nas.message_type"), step.want, body)
		}
	}

	return gnbID, ueID
}

// TS 24.501 §5.4.2.5 makes the AMF abort the ongoing registration but mandates no
// specific abort message, so either form (UE Context Release Command or
// Registration Reject) is conformant and only completing it is disqualifying.
func Test5GSecurityModeReject(t *testing.T) {
	gnbID, ueID := securityModePending(t)

	body := fmt.Sprintf(`{"message_type":"security_mode_reject","cause_5gmm":%d}`, cause5GMMUESecurityCapabilitiesMismatch)
	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
	}

	ngapMsg := jsonGet(resp, "ngap.message_type")
	nasMsg := jsonGet(resp, "nas.message_type")

	if nasMsg == nasRegistrationAccept {
		t.Errorf("AMF completed registration after a Security Mode Reject (TS 24.501 §5.4.2.5)\n  body: %s", resp)
	}
	if ngapMsg != ngapUEContextReleaseCommand && nasMsg != nasRegistrationReject {
		t.Errorf("AMF did not abort the procedure after a Security Mode Reject (ngap=%q nas=%q, TS 24.501 §5.4.2.5)\n  body: %s", ngapMsg, nasMsg, resp)
	}
}

// A forged AMF UE NGAP ID on the Uplink NAS Transport is an unknown local AP ID,
// so the AMF shall initiate an Error Indication procedure (TS 38.413 §10.6).
func Test5GSecurityModeReject_NGAPIDFuzz(t *testing.T) {
	gnbID, ueID := securityModePending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"security_mode_reject","cause_5gmm":23,"amf_ue_ngap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("security mode reject hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	assertSpecCompliantErrorIndication(t, body)
}
