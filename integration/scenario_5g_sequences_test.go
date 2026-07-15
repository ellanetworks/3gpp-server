// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// The returned security-mode-complete response carries the Registration Accept
// inside the Initial Context Setup Request's NAS PDU.
func completeRegistration(t *testing.T, gnbID, ueID string, regType int) []byte {
	t.Helper()

	// The 5GMM capability is re-sent only on change, so updates may omit it (TS 24.501 §5.5.1.3.2).
	regBody := `{"message_type":"registration_request","capability_5gmm":"07"}`
	if regType > 0 {
		regBody = fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d,"capability_5gmm":"07"}`, regType)
	}

	steps := []struct {
		body        string
		wantNASType string
	}{
		{regBody, nasAuthenticationRequest},
		{`{"message_type":"authentication_response"}`, nasSecurityModeCommand},
		{`{"message_type":"security_mode_complete"}`, nasRegistrationAccept},
	}

	var last []byte
	for i, step := range steps {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", step.body)
		if status != 200 {
			t.Fatalf("registration step %d: HTTP %d\n  body: %s", i, status, body)
		}
		if step.wantNASType != "" {
			if got := jsonGet(body, "nas.message_type"); got != step.wantNASType {
				t.Fatalf("registration step %d: nas.message_type = %q, want %q\n  body: %s", i, got, step.wantNASType, body)
			}
		}
		last = body
	}

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_complete"}`)
	if status != 200 {
		t.Fatalf("registration_complete: HTTP %d\n  body: %s", status, body)
	}

	return last
}

func registerThenIdle(t *testing.T, gnbID, ueID string) {
	t.Helper()

	completeRegistration(t, gnbID, ueID, registrationTypeInitial)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 || jsonGet(body, "ngap.message_type") != ngapUEContextReleaseCommand {
		t.Fatalf("release failed: HTTP %d\n  body: %s", status, body)
	}
}

func Test5GRegistration_MobilityUpdate(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	registerThenIdle(t, gnbID, ueID)

	body := fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d}`, registrationTypeMobility)
	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
	if status != 200 {
		t.Fatalf("mobility update: HTTP %d\n  body: %s", status, resp)
	}
	if got := jsonGet(resp, "nas.message_type"); got != nasRegistrationAccept {
		t.Errorf("nas.message_type = %q, want registration_accept (TS 24.501 §5.5.1.3)\n  body: %s", got, resp)
	}
}

// Re-authenticating, rejecting and re-identifying all keep security closed
// (TS 24.501 §4.4.4.3), so only a Registration Accept is disqualifying.
func Test5GRegistration_MobilityUpdateBadMAC(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	registerThenIdle(t, gnbID, ueID)

	body := fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d,"corrupt_mac":true,"timeout_ms":3000}`, registrationTypeMobility)
	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
	if status != 200 && status != 504 {
		t.Fatalf("mobility update with a bad NAS-MAC: HTTP %d, want 200 or 504\n  body: %s", status, resp)
	}

	if got := jsonGet(resp, "nas.message_type"); got == nasRegistrationAccept {
		t.Fatalf("the AMF accepted a mobility registration update whose NAS-MAC failed the integrity check; it must re-authenticate and re-activate security first (TS 24.501 §4.4.4.3)\n  body: %s", resp)
	}
}

func Test5GRegistration_PeriodicUpdate(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	registerThenIdle(t, gnbID, ueID)

	body := fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d}`, registrationTypePeriodic)
	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
	if status != 200 {
		t.Fatalf("periodic update: HTTP %d\n  body: %s", status, resp)
	}
	if got := jsonGet(resp, "nas.message_type"); got != nasRegistrationAccept {
		t.Errorf("nas.message_type = %q, want registration_accept (TS 24.501 §5.5.1.3)\n  body: %s", got, resp)
	}
}

func Test5GDeregistration_NonSwitchOff_Accept(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"deregistration_request","switch_off":0}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasDeregistrationAccept {
		t.Errorf("nas.message_type = %q, want deregistration_accept (TS 24.501 §5.5.2.2)\n  body: %s", got, body)
	}
}

func Test5GNGSetup_UnknownPLMN(t *testing.T) {
	body := `{
		"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
		"mcc":"999", "mnc":"99", "tac":"000001", "gnb_id":"0000f0",
		"name":"test-gnb-unknown-plmn", "sst":1
	}`

	status, resp := doRequest(t, "POST", "/gnb", body)
	if status != 201 {
		t.Fatalf("create gNB: HTTP %d, want 201\n  body: %s", status, resp)
	}

	gnbID := jsonGet(resp, "gnb_id")
	if gnbID != "" {
		t.Cleanup(func() { doRequest(t, "DELETE", "/gnb/"+gnbID, "") })
	}

	if got := jsonGet(resp, "ng_setup_response.message_type"); got != ngapNGSetupFailure {
		t.Errorf("ng_setup_response.message_type = %q, want NGSetupFailure (TS 38.413 §8.7.1.3)\n  body: %s", got, resp)
	}

	assertNGAPCauseMisc(t, resp, "ng_setup_response", causeMiscUnknownPLMNOrSNPN)
}

func Test5GRegistration_DuringSecurityMode(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request"}`)
	if status != 200 || jsonGet(body, "nas.message_type") != nasAuthenticationRequest {
		t.Fatalf("registration_request: HTTP %d nas=%q\n  body: %s", status, jsonGet(body, "nas.message_type"), body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"authentication_response"}`)
	if status != 200 || jsonGet(body, "nas.message_type") != nasSecurityModeCommand {
		t.Fatalf("authentication_response: HTTP %d nas=%q\n  body: %s", status, jsonGet(body, "nas.message_type"), body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request"}`)
	if status == 504 {
		t.Fatalf("registration during security mode hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
		t.Errorf("nas.message_type = %q, want authentication_request (SMC aborted, registration restarted, TS 24.501 §5.4.2.7)\n  body: %s", got, body)
	}
}
