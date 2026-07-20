// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func authChallengePending(t *testing.T) (string, string) {
	t.Helper()

	gnbID := mustCreateGNB(t)
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

	body := fmt.Sprintf(`{"message_type":"authentication_failure","5gmm_cause":%d}`, cause)

	return doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
}

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

// On a repeated cause #21 both terminating and re-synchronising again are
// conformant (TS 24.501 §5.4.1.3.7 f and NOTE 4), so only security activation fails.
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
	default:
		t.Errorf("repeated synch failure: nas.message_type = %q, want authentication_reject (TS 24.501 §5.4.1.3.7 NOTE 4) or a further authentication_request (item f)\n  body: %s", got, second)
	}
}

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

// §5.4.1.3.7 c)/d) leave the network a choice of re-identify, re-authenticate or
// reject, so only proceeding to a Security Mode Command is disqualifying.
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
			default:
				t.Errorf("nas.message_type = %q, want one of {authentication_reject, identity_request, authentication_request} (TS 24.501 §5.4.1.3.7)\n  body: %s", got, body)
			}
		})
	}
}

func Test5GAuthenticationFailure_NGAPIDFuzz(t *testing.T) {
	gnbID, ueID := authChallengePending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"authentication_failure","5gmm_cause":20,"amf_ue_ngap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("authentication failure hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	assertSpecCompliantErrorIndication(t, body)
}
