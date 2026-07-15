// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Registration Reject (TS 24.501 §5.5.1.2.5): the network rejects an initial
// registration it cannot serve. Assertions follow the spec; a failure means
// Ella Core deviates.

package integration_test

import "testing"

// createUEWithBody creates a UE from a raw JSON body and returns its ID.
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

// Test5GRegistrationReject_UnknownUE registers a UE whose SUPI is not provisioned
// in the core (null-scheme SUCI, so the SUPI is derivable but unknown). The
// network cannot serve it and must reject the registration (TS 24.501
// §5.5.1.2.5). The spec leaves the 5GMM cause to the network ("an appropriate
// 5GMM cause value"), so only the rejection itself is asserted.
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

// Test5GRegistrationReject_InvalidHomeNetworkKey registers with a Profile A SUCI
// concealed under an X25519 public key that does not match the core's. The core
// cannot de-conceal the SUCI, so it cannot derive the UE identity and must
// reject with 5GMM cause #9 "UE identity cannot be derived by the network" —
// the cause defined for exactly this condition (TS 24.501 §9.11.3.2).
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

	assertNASCause(t, body, "nas.cause_5gmm", cause5GMMUEIdentityCannotBeDerived)
}
