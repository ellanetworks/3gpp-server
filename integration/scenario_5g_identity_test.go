// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Identity procedure (TS 24.501 §5.4.3): when the AMF cannot resolve the
// identity a UE presented, it sends an Identity Request and the UE answers with
// an Identity Response carrying the requested identity.

package integration_test

import "testing"

// identityRequestPending registers with a 5G-GUTI the AMF does not know, which
// makes the AMF respond with an Identity Request (asking for the SUCI). It
// returns the gNB/UE so the caller can drive the Identity Response.
func identityRequestPending(t *testing.T) (string, string) {
	t.Helper()

	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	// A syntactically valid 5G-GUTI (type 0xf2) for PLMN 001/01 with a 5G-TMSI
	// the AMF has never allocated, so it cannot derive the UE's identity.
	const unknownGUTI = "f200f11001004012345678"

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request","mobile_identity_override":"`+unknownGUTI+`"}`)
	if status != 200 {
		t.Fatalf("registration_request: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasIdentityRequest {
		t.Fatalf("nas.message_type = %q, want identity_request (TS 24.501 §5.4.3)\n  body: %s", got, body)
	}

	return gnbID, ueID
}

// Test5GIdentity_UnknownGUTI answers the Identity Request with the UE's SUCI,
// after which the AMF can derive the identity and starts authentication.
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

// Test5GIdentity_MalformedSUCI answers the Identity Request with a SUCI-typed but
// undecodable identity. The AMF cannot derive a SUPI from it, so it must not
// authenticate the underivable identity. TS 24.501 §5.4.3.4/§5.4.3.6 mandate no
// specific reaction (re-request or reject is implementation latitude), so we
// assert only the invariant: the procedure must not advance to authentication.
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

// Test5GIdentity_NGAPIDFuzz forges the AMF UE NGAP ID on the Identity Response's
// Uplink NAS Transport. That is an unknown local AP ID, so the AMF shall
// initiate an Error Indication procedure (TS 38.413 §10.6).
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
