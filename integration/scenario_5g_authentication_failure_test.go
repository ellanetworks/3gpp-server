// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Authentication Failure (TS 24.501 §5.4.1.3.6 / §5.4.1.3.7): the UE rejects an
// Authentication Request with a 5GMM cause, and the network's mandated reaction
// depends on that cause.

package integration_test

import (
	"fmt"
	"testing"
)

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

// On cause #21 with a valid AUTS the network shall re-synchronise and initiate
// authentication again (TS 24.501 §5.4.1.3.7 f).
func Test5GAuthenticationFailure_SynchFailure(t *testing.T) {
	gnbID, ueID := authChallengePending(t)

	status, body := sendAuthFailure(t, gnbID, ueID, cause5GMMSynchFailure)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
		t.Errorf("nas.message_type = %q, want authentication_request (TS 24.501 §5.4.1.3.7 f)\n  body: %s", got, body)
	}
}

// On the first cause #21 the network shall re-synchronise from the AUTS and
// initiate authentication again (TS 24.501 §5.4.1.3.7 f). On a repeat, NOTE 4 of
// the same subclause only permits terminating with an AUTHENTICATION REJECT, so
// re-synchronising once more is equally conformant; the binding invariant is
// that an unauthenticated UE must not reach security activation.
func Test5GAuthenticationFailure_RepeatedSynchFailure(t *testing.T) {
	gnbID, ueID := authChallengePending(t)

	status, first := sendAuthFailure(t, gnbID, ueID, cause5GMMSynchFailure)
	if status != 200 {
		t.Fatalf("first synch failure: HTTP %d, want 200\n  body: %s", status, first)
	}

	if got := jsonGet(first, "nas.message_type"); got != nasAuthenticationRequest {
		t.Fatalf("first synch failure: nas.message_type = %q, want a fresh authentication_request (TS 24.501 §5.4.1.3.7 f)\n  body: %s", got, first)
	}

	status, second := sendAuthFailure(t, gnbID, ueID, cause5GMMSynchFailure)
	if status != 200 {
		t.Fatalf("repeated synch failure: HTTP %d, want 200\n  body: %s", status, second)
	}

	switch got := jsonGet(second, "nas.message_type"); got {
	case nasAuthenticationReject, nasAuthenticationRequest:
		// Both permitted: terminate (§5.4.1.3.7 NOTE 4) or re-synchronise again (item f).
	default:
		t.Errorf("repeated synch failure: nas.message_type = %q, want authentication_reject (TS 24.501 §5.4.1.3.7 NOTE 4) or a further authentication_request (item f)\n  body: %s", got, second)
	}
}

// On cause #71 the network selects a new ngKSI and re-sends the challenge
// (TS 24.501 §5.4.1.3.7 e).
func Test5GAuthenticationFailure_NgKSIAlreadyInUse(t *testing.T) {
	gnbID, ueID := authChallengePending(t)

	status, body := sendAuthFailure(t, gnbID, ueID, cause5GMMngKSIAlreadyInUse)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
		t.Errorf("nas.message_type = %q, want authentication_request (TS 24.501 §5.4.1.3.7 e)\n  body: %s", got, body)
	}
}

// For causes #20 and #26, TS 24.501 §5.4.1.3.7 c)/d) leave the network a choice:
// re-identify, re-authenticate, or reject. The binding requirement is that it
// must not proceed with the procedure, so a Security Mode Command is never valid.
func Test5GAuthenticationFailure_MACFailure(t *testing.T) {
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

// A forged AMF UE NGAP ID on the Uplink NAS Transport is an unknown local AP ID,
// which the AMF must answer with an Error Indication (TS 38.413 §8.6.3).
func Test5GAuthenticationFailure_NGAPIDFuzz(t *testing.T) {
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
