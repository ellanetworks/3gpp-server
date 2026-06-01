//go:build integration

// Identity procedure (TS 24.501 §5.4.3): when the AMF cannot resolve the
// identity a UE presented, it sends an Identity Request and the UE answers with
// an Identity Response carrying the requested identity.

package integration_test

import "testing"

// TestIdentity_UnknownGUTI registers with a 5G-GUTI the AMF does not know, so
// the AMF asks for the SUCI (Identity Request). The UE answers with its SUCI
// (Identity Response), after which the AMF starts authentication.
func TestIdentity_UnknownGUTI(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	// A syntactically valid 5G-GUTI (type 0xf2) for PLMN 001/01 with a 5G-TMSI
	// the AMF has never allocated, so it cannot derive the UE's identity.
	unknownGUTI := "f200f11001004012345678"

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request","mobile_identity_override":"`+unknownGUTI+`"}`)
	if status != 200 {
		t.Fatalf("registration_request: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasIdentityRequest {
		t.Fatalf("nas.message_type = %q, want identity_request (TS 24.501 §5.4.3)\n  body: %s", got, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"identity_response"}`)
	if status != 200 {
		t.Fatalf("identity_response: HTTP %d\n  body: %s", status, body)
	}

	// With the SUCI resolved, the AMF proceeds to authenticate the UE.
	if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
		t.Errorf("nas.message_type = %q, want authentication_request\n  body: %s", got, body)
	}
}
