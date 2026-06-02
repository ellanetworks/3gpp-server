//go:build integration

// Authentication Failure (TS 24.501 §5.4.1.3.6 / §5.4.1.3.7): the UE rejects an
// Authentication Request with a 5GMM cause. The network's mandated reaction
// depends on the cause. Assertions follow the spec; a failure means Ella Core
// deviates from TS 24.501.

package integration_test

import (
	"fmt"
	"testing"
)

// authChallengePending registers a UE and returns once the AMF has sent the
// Authentication Request (the UE is in the authentication phase).
func authChallengePending(t *testing.T) (string, string) {
	t.Helper()

	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request"}`)
	if status != 200 || jsonGet(body, "nas.message_type") != nasAuthenticationRequest {
		t.Fatalf("registration_request: HTTP %d nas=%q\n  body: %s", status, jsonGet(body, "nas.message_type"), body)
	}

	return gnbID, ueID
}

func sendAuthFailure(t *testing.T, gnbID, ueID string, cause int) (int, []byte) {
	t.Helper()

	body := fmt.Sprintf(`{"message_type":"authentication_failure","cause_5gmm":%d}`, cause)

	return doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
}

// TestAuthenticationFailure_SynchFailure sends cause #21 with a valid AUTS. Per
// TS 24.501 §5.4.1.3.7 f) the network shall re-synchronise (fetch new vectors)
// and initiate authentication again — i.e. send a new Authentication Request.
func TestAuthenticationFailure_SynchFailure(t *testing.T) {
	gnbID, ueID := authChallengePending(t)

	status, body := sendAuthFailure(t, gnbID, ueID, cause5GMMSynchFailure)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
		t.Errorf("nas.message_type = %q, want authentication_request (TS 24.501 §5.4.1.3.7 f)\n  body: %s", got, body)
	}
}

// TestAuthenticationFailure_NgKSIAlreadyInUse sends cause #71. Per TS 24.501
// §5.4.1.3.7 e) the network selects a new ngKSI and re-sends the challenge — a
// new Authentication Request.
func TestAuthenticationFailure_NgKSIAlreadyInUse(t *testing.T) {
	gnbID, ueID := authChallengePending(t)

	status, body := sendAuthFailure(t, gnbID, ueID, cause5GMMngKSIAlreadyInUse)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
		t.Errorf("nas.message_type = %q, want authentication_request (TS 24.501 §5.4.1.3.7 e)\n  body: %s", got, body)
	}
}

// TestAuthenticationFailure_MACFailure covers the causes (#20 MAC failure, #26
// non-5G unacceptable) where TS 24.501 §5.4.1.3.7 c)/d) leave the network a
// choice: re-identify, re-authenticate, or reject. The binding requirement is
// that the network must NOT proceed with the procedure — so the response must
// be one of those rejection/retry reactions, never a Security Mode Command.
func TestAuthenticationFailure_MACFailure(t *testing.T) {
	for _, cause := range []int{cause5GMMMACFailure, cause5GMMNon5GAuthenticationUnacceptable} {
		t.Run(fmt.Sprintf("cause-%d", cause), func(t *testing.T) {
			gnbID, ueID := authChallengePending(t)

			status, body := sendAuthFailure(t, gnbID, ueID, cause)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			switch got := jsonGet(body, "nas.message_type"); got {
			case nasAuthenticationReject, nasIdentityRequest, nasAuthenticationRequest:
				// Spec-permitted reactions (§5.4.1.3.7 c)/d), §5.4.1.3.5).
			default:
				t.Errorf("nas.message_type = %q, want one of {authentication_reject, identity_request, authentication_request} (TS 24.501 §5.4.1.3.7)\n  body: %s", got, body)
			}
		})
	}
}

// TestAuthenticationFailure_NGAPIDFuzz forges the AMF UE NGAP ID on the
// Authentication Failure's Uplink NAS Transport. The AMF does not recognise the
// ID and answers with an Error Indication (TS 38.413 §8.6.3).
func TestAuthenticationFailure_NGAPIDFuzz(t *testing.T) {
	gnbID, ueID := authChallengePending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"authentication_failure","cause_5gmm":20,"amf_ue_ngap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("authentication failure hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	assertSpecCompliantErrorIndication(t, body)
}
