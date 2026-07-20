// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test5GBadMACSecurityModeComplete(t *testing.T) {
	gnbID, ueID := securityModePending(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"security_mode_complete","corrupt_mac":true}`)

	if status == 200 {
		if got := jsonGet(body, "ngap.message_type"); got == ngapInitialContextSetupRequest {
			t.Fatalf("AMF proceeded to Initial Context Setup on a corrupted Security Mode Complete (TS 24.501 §4.4.4.3)\n  body: %s", body)
		}
	}

	freshGNB := mustCreateGNB(t)
	doRegistrationFlow(t, freshGNB, mustCreateUE(t, freshGNB))
}

// TS 24.501 §4.4.4.3 mandates SERVICE REJECT #9 only while the UE has no
// emergency PDU session.
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

	if got := jsonGet(body, "nas.5gmm_cause"); got != "9" {
		t.Errorf("service_reject 5gmm_cause = %q, want 9 (TS 24.501 §4.4.4.3)\n  body: %s", got, body)
	}
}

func Test5GServiceRequestStaleNASCount(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"service_request"}`)
	if status != 200 || jsonGet(body, "ngap.message_type") != ngapInitialContextSetupRequest {
		t.Fatalf("first service request did not re-establish: HTTP %d, %q\n  body: %s", status, jsonGet(body, "ngap.message_type"), body)
	}

	if status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"ue_context_release_request"}`); status != 200 {
		t.Fatalf("release: HTTP %d\n  body: %s", status, body)
	}

	// A stale COUNT fails integrity verification (TS 24.501 §4.4.3.1, §4.4.3.2), so
	// §4.4.4.3 applies and the reply is a SERVICE REJECT, not a discard.
	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","nas_count":0,"timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("no reply to a stale-COUNT Service Request (HTTP %d) — the AMF must SERVICE REJECT #9 (TS 24.501 §4.4.4.3)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasServiceReject {
		t.Fatalf("nas.message_type = %q, want service_reject (TS 24.501 §4.4.4.3)\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.5gmm_cause"); got != "9" {
		t.Errorf("service_reject 5gmm_cause = %q, want 9 (TS 24.501 §4.4.4.3)\n  body: %s", got, body)
	}
}

func Test5GForgedNGAPIDInjection(t *testing.T) {
	gnbID := mustCreateGNB(t)
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

func Test5GNASReplay(t *testing.T) {
	gnbID := mustCreateGNB(t)
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

	freshGNB := mustCreateGNB(t)
	doRegistrationFlow(t, freshGNB, mustCreateUE(t, freshGNB))
}
