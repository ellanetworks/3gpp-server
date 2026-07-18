// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func createUEWithBody(t *testing.T, gnbID, body string) string {
	t.Helper()

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create ue: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	if ueID == "" {
		t.Fatalf("create ue: no ue_id in response: %s", resp)
	}

	return ueID
}

// TS 24.501 §5.5.1.2.5 leaves the 5GMM cause to the network, so only the
// rejection itself is asserted.
func Test5GRegistrationReject_UnknownUE(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := createUEWithBody(t, gnbID, `{
		"supi": "imsi-001019999999999",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": "internet",
		"routing_indicator": "0", "protection_scheme": "0", "public_key_id": "0",
		"imeisv": "1122334455667788"
	}`)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request"}`)
	if status != 200 {
		t.Fatalf("registration_request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasRegistrationReject {
		t.Errorf("nas.message_type = %q, want registration_reject (TS 24.501 §5.5.1.2.5)\n  body: %s", got, body)
	}
}

func Test5GRegistrationReject_InvalidHomeNetworkKey(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := createUEWithBody(t, gnbID, `{
		"supi": "imsi-001010000000001",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": "internet",
		"routing_indicator": "0", "protection_scheme": "1", "public_key_id": "1",
		"public_key_hex": "68863be1b86661a38a720217ec17170c5feda91e891cb3f53d4b74fbabb10247",
		"imeisv": "1122334455667788"
	}`)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request"}`)
	if status != 200 {
		t.Fatalf("registration_request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasRegistrationReject {
		t.Fatalf("nas.message_type = %q, want registration_reject\n  body: %s", got, body)
	}

	assertNASCause(t, body, "nas.5gmm_cause", cause5GMMUEIdentityCannotBeDerived)
}
