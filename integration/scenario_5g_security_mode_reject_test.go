// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Security Mode Reject (TS 24.501 §5.4.2.5): the UE rejects a Security Mode
// Command. Per the spec the AMF shall abort the ongoing (registration)
// procedure. Assertions follow the spec; a failure means Ella Core deviates.

package integration_test

import (
	"fmt"
	"testing"
)

// securityModePending drives registration to the point where the AMF has sent
// the Security Mode Command (the UE is in the security-mode phase).
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

// Test5GSecurityModeReject sends a Security Mode Reject (#23 UE security
// capabilities mismatch). Per TS 24.501 §5.4.2.5 the AMF shall abort the
// ongoing registration — so it must not complete it. The spec does not mandate
// a specific abort message, so we accept either form of abort (UE Context
// Release Command, or a Registration Reject) and require it not be accepted.
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

// Test5GSecurityModeReject_NGAPIDFuzz forges the AMF UE NGAP ID on the Security
// Mode Reject's Uplink NAS Transport. That is an unknown local AP ID, so the
// AMF shall initiate an Error Indication procedure (TS 38.413 §10.6).
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
