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

// TestIdentity_UnknownGUTI answers the Identity Request with the UE's SUCI,
// after which the AMF can derive the identity and starts authentication.
func TestIdentity_UnknownGUTI(t *testing.T) {
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

// TestIdentity_MalformedSUCI answers the Identity Request with a SUCI-typed but
// undecodable identity. The AMF cannot derive the SUPI, so it must not proceed
// to authentication; per TS 24.501 §5.4.3 it re-initiates identification.
func TestIdentity_MalformedSUCI(t *testing.T) {
	gnbID, ueID := identityRequestPending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"identity_response","mobile_identity_override":"01deadbeef"}`)
	if status != 200 {
		t.Fatalf("identity_response: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasIdentityRequest {
		t.Errorf("nas.message_type = %q, want identity_request (AMF re-requests, §5.4.3)\n  body: %s", got, body)
	}
}

// TestIdentity_Fuzz sends malformed Identity Response NAS payloads. The AMF must
// answer, never silently drop (no 504).
func TestIdentity_Fuzz(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		wantNGAPMsgType  string
		wantNASMsgType   string
		wantNASCause5GMM int
	}{
		{
			name:            "raw NAS empty → ErrorIndication",
			body:            `{"message_type":"identity_response","raw_nas_pdu":""}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:             "raw NAS garbage → 5GMM STATUS #111",
			body:             `{"message_type":"identity_response","raw_nas_pdu":"deadbeef"}`,
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantNASMsgType:   nasStatus5GMM,
			wantNASCause5GMM: cause5GMMProtocolErrorUnspecified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID, ueID := identityRequestPending(t)

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tt.body)
			if status == 504 {
				t.Fatalf("identity response hung (HTTP 504)\n  body: %s", body)
			}
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			if got := jsonGet(body, "ngap.message_type"); got != tt.wantNGAPMsgType {
				t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, tt.wantNGAPMsgType, body)
			}
			if tt.wantNASMsgType != "" {
				if got := jsonGet(body, "nas.message_type"); got != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q\n  body: %s", got, tt.wantNASMsgType, body)
				}
			}
			assertNASCause(t, body, "nas.cause_5gmm", tt.wantNASCause5GMM)
		})
	}
}

// TestIdentity_NGAPIDFuzz forges the AMF UE NGAP ID on the Identity Response's
// Uplink NAS Transport. The AMF does not recognise the ID and answers with an
// Error Indication (TS 38.413 §8.6.3), never silently dropping the message.
func TestIdentity_NGAPIDFuzz(t *testing.T) {
	gnbID, ueID := identityRequestPending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"identity_response","amf_ue_ngap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("identity response hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("ngap.message_type = %q, want ErrorIndication\n  body: %s", got, body)
	}
}
