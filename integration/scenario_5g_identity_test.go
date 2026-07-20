// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func identityRequestPending(t *testing.T) (string, string) {
	t.Helper()

	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)

	// A syntactically valid 5G-GUTI (type 0xf2) whose 5G-TMSI the AMF never allocated.
	const unknownGUTI = "f200f11001004012345678"

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request","mobile_identity_override":"`+unknownGUTI+`"}`)
	if status != 200 {
		t.Fatalf("registration_request: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasIdentityRequest {
		t.Fatalf("nas.message_type = %q, want identity_request (TS 24.501 §5.4.3)\n  body: %s", got, body)
	}

	// Identity type "001" is SUCI (TS 24.501 §9.11.3.3).
	if got := jsonGet(body, "nas.identity_type"); got != identityTypeSUCI {
		t.Fatalf("nas.identity_type = %q, want %s (SUCI) — the AMF cannot derive the SUPI from an unknown 5G-GUTI (TS 24.501 §9.11.3.3)\n  body: %s", got, identityTypeSUCI, body)
	}

	return gnbID, ueID
}

func Test5GIdentity_UnknownGUTI(t *testing.T) {
	gnbID, ueID := identityRequestPending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"identity_response"}`)
	if status != 200 {
		t.Fatalf("identity_response: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
		t.Errorf("nas.message_type = %q, want authentication_request\n  body: %s", got, body)
	}
}

// TS 24.501 §5.4.3.4/§5.4.3.6 mandate no reaction to an undecodable SUCI, so only
// the AMF not authenticating an underivable identity is asserted.
func Test5GIdentity_MalformedSUCI(t *testing.T) {
	gnbID, ueID := identityRequestPending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"identity_response","mobile_identity_override":"01deadbeef"}`)
	if status != 200 {
		t.Fatalf("identity_response: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got == nasAuthenticationRequest {
		t.Errorf("AMF advanced to authentication with an underivable identity (TS 24.501 §5.4.3)\n  body: %s", body)
	}
}

func Test5GIdentity_NGAPIDFuzz(t *testing.T) {
	gnbID, ueID := identityRequestPending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"identity_response","amf_ue_ngap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("identity response hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	assertSpecCompliantErrorIndication(t, body)
}
