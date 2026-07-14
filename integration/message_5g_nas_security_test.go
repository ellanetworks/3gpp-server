// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// 5G NAS security negative tests: a message failing integrity must be discarded
// (TS 24.501 §4.4.4.3), a stale/replayed NAS COUNT must not be accepted
// (§4.4.3), and a NAS PDU carrying a forged UE NGAP ID must draw an Error
// Indication (TS 38.413 §8.7.5.2). A failure means Ella Core deviates.

package integration_test

import (
	"testing"
)

// Test5GBadMACSecurityModeComplete checks the AMF discards a Security Mode
// Complete whose NAS-MAC is corrupted (TS 24.501 §4.4.4.3): it must not proceed
// to Initial Context Setup.
func Test5GBadMACSecurityModeComplete(t *testing.T) {
	gnbID, ueID := securityModePending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"security_mode_complete","corrupt_mac":true}`)

	if status == 200 {
		if got := jsonGet(body, "ngap.message_type"); got == ngapInitialContextSetupRequest {
			t.Fatalf("AMF proceeded to Initial Context Setup on a corrupted Security Mode Complete (TS 24.501 §4.4.4.3)\n  body: %s", body)
		}
	}

	// The AMF stays healthy: a fresh UE completes registration.
	freshGnB := mustCreateGnB(t)
	doRegistrationFlow(t, freshGnB, mustCreateUE(t, freshGnB))
}

// Test5GBadMACServiceRequest checks that a Service Request failing the integrity
// check is rejected with SERVICE REJECT #9 (TS 24.501 §4.4.4.3): "If a SERVICE
// REQUEST ... fails the integrity check and the UE has only non-emergency PDU
// sessions established, the AMF shall send the SERVICE REJECT message with 5GMM
// cause #9 'UE identity cannot be derived by the network'."
func Test5GBadMACServiceRequest(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","corrupt_mac":true,"timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("no reply to a corrupted Service Request (HTTP %d) — the AMF must SERVICE REJECT #9 (TS 24.501 §4.4.4.3)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasServiceReject {
		t.Fatalf("nas.message_type = %q, want service_reject (TS 24.501 §4.4.4.3)\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.cause_5gmm"); got != "9" {
		t.Errorf("service_reject cause_5gmm = %q, want 9 (TS 24.501 §4.4.4.3)\n  body: %s", got, body)
	}
}

// Test5GServiceRequestStaleNASCount checks a Service Request carrying a stale
// uplink NAS COUNT does not re-establish (TS 24.501 §4.4.3.1: the estimated
// COUNT must be higher than the stored value).
func Test5GServiceRequestStaleNASCount(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"service_request"}`)
	if status != 200 || jsonGet(body, "ngap.message_type") != ngapInitialContextSetupRequest {
		t.Fatalf("first service request did not re-establish: HTTP %d, %q\n  body: %s", status, jsonGet(body, "ngap.message_type"), body)
	}

	if status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"ue_context_release_request"}`); status != 200 {
		t.Fatalf("release: HTTP %d\n  body: %s", status, body)
	}

	// A stale NAS COUNT fails integrity verification (§4.4.3.1: the estimated COUNT
	// is selected higher than the stored value; §4.4.3.2: a COUNT is accepted only
	// if integrity verifies), so §4.4.4.3 applies: SERVICE REJECT #9.
	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","nas_count":0,"timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("no reply to a stale-COUNT Service Request (HTTP %d) — the AMF must SERVICE REJECT #9 (TS 24.501 §4.4.4.3)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasServiceReject {
		t.Fatalf("nas.message_type = %q, want service_reject (TS 24.501 §4.4.4.3)\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.cause_5gmm"); got != "9" {
		t.Errorf("service_reject cause_5gmm = %q, want 9 (TS 24.501 §4.4.4.3)\n  body: %s", got, body)
	}
}

// Test5GForgedNGAPIDInjection injects a NAS PDU on the existing association with
// a forged AMF UE NGAP ID naming no known connection; the AMF must answer with
// an Error Indication (TS 38.413 §8.7.5.2), not route it.
func Test5GForgedNGAPIDInjection(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"inject_nas","amf_ue_ngap_id_override":99999,"raw_nas_pdu":"7e00","timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("inject_nas: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Fatalf("ngap.message_type = %q, want ErrorIndication for a forged AMF UE NGAP ID (TS 38.413 §8.7.5.2)\n  body: %s", got, body)
	}

	assertSpecCompliantErrorIndication(t, body)
}

// Test5GNASReplay replays the last secured uplink NAS PDU verbatim (same NAS
// COUNT); the AMF must not re-process it (TS 24.501 §4.4.3.2).
func Test5GNASReplay(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"inject_nas","replay_last":true,"timeout_ms":1500}`)
	if status != 200 {
		t.Fatalf("inject_nas replay: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got == ngapInitialContextSetupRequest {
		t.Fatalf("AMF re-processed a replayed NAS message (TS 24.501 §4.4.3.2)\n  body: %s", body)
	}

	freshGnB := mustCreateGnB(t)
	doRegistrationFlow(t, freshGnB, mustCreateUE(t, freshGnB))
}
