// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// IP-pool exhaustion (TS 24.501 §6.4.1.x): when the PDU session cannot be
// established because no address can be allocated, the SMF shall reject the PDU
// SESSION ESTABLISHMENT REQUEST with 5GSM cause #26 "insufficient resources".
// The condition is transient — once a session releases its address a retry
// succeeds (§6.2.12). A failing test means Ella Core deviates from the mandated
// reject, cause, or transience behaviour.

package integration_test

import (
	"fmt"
	"testing"
)

// exhaustDNN is provisioned in TestMain with an IPv4 /30 pool, i.e. exactly two
// allocatable host addresses.
const exhaustDNN = "exhaust"

func Test5GPDUSessionEstablishment_IPPoolExhausted(t *testing.T) {
	gnbID := mustCreateGnB(t)

	// Two registered UEs fill the /30 pool (addresses .1 and .2).
	ue1 := newExhaustUE(t, gnbID, testSUPI(1))
	mustEstablishExhaust(t, gnbID, ue1)

	ue2 := newExhaustUE(t, gnbID, testSUPI(2))
	mustEstablishExhaust(t, gnbID, ue2)

	// A third UE cannot be allocated an address; the SMF must reject with #26.
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

	assertNASCause(t, body, "nas.cause_5gsm", cause5GSMInsufficientResources)

	// The Establishment Reject is the complete response (TS 24.501 §6.4.1.x): a
	// successful UL NAS transport carrying an SMF reject is not a 5GMM protocol
	// error, so the AMF must not also emit a 5GMM STATUS. Any follow-up NAS
	// message for this UE is therefore a violation.
	if st, extra := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ue3+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":3000}`); st == 200 {
		t.Errorf("a PDU Session Establishment Reject must be the complete response (TS 24.501 §6.4.1.x), but a follow-up NAS message arrived — the AMF emits a spurious 5GMM STATUS:\n  %s", extra)
	}

	// Transience (TS 24.501 §6.2.12): #26 is a temporary condition. Freeing an
	// address must let a fresh establishment succeed, confirming the shortage was
	// not permanent and the rejected attempt left the pool consistent.
	//
	// A UE-requested release runs as a network-requested release (TS 24.501
	// §6.4.3.3 → §6.3.3): the SMF frees the address on Release Complete, not on the
	// bare Release Request, so the UE must finish the handshake before the lease
	// returns to the pool.
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

// newExhaustUE creates and registers a UE that targets the tiny-pool "exhaust"
// DNN, and de-registers it on cleanup so its IP leases are released and the
// shared pool stays clean across runs.
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

// mustEstablishExhaust establishes a PDU session on the exhaust DNN and requires
// it to be accepted (the pool still has a free address).
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
