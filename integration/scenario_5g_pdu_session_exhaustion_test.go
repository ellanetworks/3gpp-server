// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// exhaustDNN is provisioned in TestMain with an IPv4 /30 pool: two host addresses.
const exhaustDNN = "exhaust"

func Test5GPDUSessionEstablishment_IPPoolExhausted(t *testing.T) {
	gnbID := mustCreateGNB(t)

	ue1 := newExhaustUE(t, gnbID, testSUPI(1))
	mustEstablishExhaust(t, gnbID, ue1)

	ue2 := newExhaustUE(t, gnbID, testSUPI(2))
	mustEstablishExhaust(t, gnbID, ue2)

	ue3 := newExhaustUE(t, gnbID, testSUPI(3))

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ue3+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status == 504 {
		t.Fatalf("no response to establishment on an exhausted pool; TS 24.501 §6.4.1.x requires an Establishment Reject with 5GSM cause #26\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapDownlinkNASTransport {
		t.Fatalf("ngap.message_type = %q, want DownlinkNASTransport (reject)\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentReject {
		t.Errorf("nas.inner_nas_message_type = %q, want pdu_session_establishment_reject\n  body: %s", got, body)
	}

	assertNASCause(t, body, "nas.5gsm_cause", cause5GSMInsufficientResources)

	// The Establishment Reject is the complete response, so any follow-up NAS is a violation.
	if st, extra := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ue3+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":3000}`); st == 200 {
		t.Errorf("a PDU Session Establishment Reject must be the complete response (TS 24.501 §6.4.1.x), but a follow-up NAS message arrived — the AMF emits a spurious 5GMM STATUS:\n  %s", extra)
	}

	// The SMF frees the address only on Release Complete (TS 24.501 §6.4.3.3 → §6.3.3),
	// so the handshake must finish before the lease returns to the pool.
	if st, rel := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ue1+"/ngap",
		`{"message_type":"pdu_session_release_request"}`); st != 200 {
		t.Fatalf("release on ue1: HTTP %d\n  body: %s", st, rel)
	}

	if st, rel := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ue1+"/ngap",
		`{"message_type":"pdu_session_release_complete"}`); st != 200 {
		t.Fatalf("release_complete on ue1: HTTP %d\n  body: %s", st, rel)
	}

	ue4 := newExhaustUE(t, gnbID, testSUPI(4))
	mustEstablishExhaust(t, gnbID, ue4)
}

// The cleanup de-registration returns the UE's IP leases to the shared pool.
func newExhaustUE(t *testing.T, gnbID, supi string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"supi": "%s",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": %q, "pdu_session_type": %d,
		"routing_indicator": "0", "protection_scheme": "0", "public_key_id": "0",
		"imeisv": "1122334455667788"
	}`, supi, exhaustDNN, pduSessionTypeIPv4)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create ue %s: HTTP %d: %s", supi, status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	if ueID == "" {
		t.Fatalf("create ue %s: no ue_id", supi)
	}

	doRegistrationFlow(t, gnbID, ueID)

	t.Cleanup(func() {
		doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"deregistration_request"}`)
	})

	return ueID
}

func mustEstablishExhaust(t *testing.T, gnbID, ueID string) {
	t.Helper()

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("establish on %s: HTTP %d\n  body: %s", ueID, status, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentAccept {
		t.Fatalf("establish on %s: inner = %q, want pdu_session_establishment_accept (pool should have a free address)\n  body: %s", ueID, got, body)
	}
}
