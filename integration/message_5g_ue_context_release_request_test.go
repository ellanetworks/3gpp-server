// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Tests for the gNB-initiated UE Context Release Request (TS 38.413 §8.3.2).
// The gNB asks the AMF to release the UE's logical NG connection; the AMF
// answers with a UE Context Release Command, the gNB replies with Complete,
// and the UE transitions to CM-IDLE while remaining RM-REGISTERED.

package integration_test

import (
	"fmt"
	"strings"
	"testing"
)

// TestUEContextReleaseRequest covers the happy path and valid cause variations.
// In every case a registered UE's release request must elicit a UE Context
// Release Command from the AMF.
func Test5GUEContextReleaseRequest(t *testing.T) {
	// releaseCause of -1 omits the IE so the server applies its default.
	tests := []struct {
		name         string
		releaseCause int
	}{
		{name: "default cause", releaseCause: -1},
		{name: "user-inactivity", releaseCause: causeRadioNetworkUserInactivity},
		{name: "release-due-to-ngran-generated-reason", releaseCause: causeRadioNetworkReleaseDueToNgranGeneratedReason},
		{name: "unspecified", releaseCause: causeRadioNetworkUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGnB(t)
			ueID := mustCreateUE(t, gnbID)

			doRegistrationFlow(t, gnbID, ueID)

			body := `{"message_type":"ue_context_release_request"}`
			if tt.releaseCause >= 0 {
				body = fmt.Sprintf(`{"message_type":"ue_context_release_request","release_cause":%d}`, tt.releaseCause)
			}

			status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
			}

			if got := jsonGet(resp, "ngap.message_type"); got != ngapUEContextReleaseCommand {
				t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, ngapUEContextReleaseCommand, resp)
			}
		})
	}
}

// TestUEContextReleaseRequest_AfterPDUSession releases a UE that has an active
// PDU session. The AMF should still release the whole UE context.
func Test5GUEContextReleaseRequest_AfterPDUSession(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("pdu_session: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, ngapUEContextReleaseCommand, body)
	}
}

// TestUEContextReleaseRequest_ThenReregister verifies the release frees only the
// NG/N2 logical connection: the UE stays RM-REGISTERED and the AMF keeps its
// context, so returning from CM-IDLE is a Mobility Registration Update that the
// AMF accepts by reusing the retained 5G NAS security context — no fresh
// authentication (TS 24.501 §5.5.1.3, TS 23.501 §5.3.2).
func Test5GUEContextReleaseRequest_ThenReregister(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("release: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Fatalf("release ngap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}

	// Return from CM-IDLE: a Mobility Registration Update on a fresh NG connection,
	// integrity-protected with the retained security context. The AMF reuses the
	// context and accepts directly.
	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request","registration_type":2}`)
	if status != 200 {
		t.Fatalf("re-register: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasRegistrationAccept {
		t.Errorf("re-register nas.message_type = %q, want registration_accept\n  body: %s", got, body)
	}
}

// TestUEContextReleaseRequest_NGAPIDFuzz mutates the AMF/RAN UE NGAP IDs. Per
// TS 38.413 §8.7.5.2 an incorrect ID must elicit an Error Indication, not a
// release command.
func Test5GUEContextReleaseRequest_NGAPIDFuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantNGAPMsgType string
	}{
		{
			name:            "AMF UE NGAP ID = 0 (never allocated)",
			body:            `{"message_type":"ue_context_release_request","amf_ue_ngap_id_override":0}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "AMF UE NGAP ID = 99999 (never allocated)",
			body:            `{"message_type":"ue_context_release_request","amf_ue_ngap_id_override":99999}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "RAN UE NGAP ID = 99999 (never allocated)",
			body:            `{"message_type":"ue_context_release_request","ran_ue_ngap_id_override":99999}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "both IDs forged",
			body:            `{"message_type":"ue_context_release_request","amf_ue_ngap_id_override":99999,"ran_ue_ngap_id_override":99999}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGnB(t)
			ueID := mustCreateUE(t, gnbID)

			doRegistrationFlow(t, gnbID, ueID)

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tt.body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			if got := jsonGet(body, "ngap.message_type"); got != tt.wantNGAPMsgType {
				t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, tt.wantNGAPMsgType, body)
			}

			if tt.wantNGAPMsgType == ngapErrorIndication {
				assertSpecCompliantErrorIndication(t, body)
			}
		})
	}
}

// TestUEContextReleaseRequest_BeforeRegistration sends a release request for a
// UE the AMF has never seen (no Initial UE Message yet). The AMF has no context
// for the RAN UE NGAP ID and must answer with Error Indication.
func Test5GUEContextReleaseRequest_BeforeRegistration(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("ngap.message_type = %q, want ErrorIndication\n  body: %s", got, body)
	}
}

// TestUEContextReleaseRequest_DoubleRelease releases twice. The second request
// references a context the AMF already tore down, so it must answer with Error
// Indication rather than a second release command.
func Test5GUEContextReleaseRequest_DoubleRelease(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("first release: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Fatalf("first release ngap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("second release: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("second release ngap.message_type = %q, want ErrorIndication\n  body: %s", got, body)
	}
}

// TestUEContextReleaseRequest_OutOfRangeCause sends a radio-network Cause value
// outside the enumerated range. The server must not hang or 5xx — the AMF
// should still process the request (the Cause IE is informational).
func Test5GUEContextReleaseRequest_OutOfRangeCause(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	body := fmt.Sprintf(`{"message_type":"ue_context_release_request","release_cause":%d}`, causeRadioNetworkOutOfRange)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
	}

	got := jsonGet(resp, "ngap.message_type")
	if got != ngapUEContextReleaseCommand && got != ngapErrorIndication {
		t.Errorf("ngap.message_type = %q, want UEContextReleaseCommand or ErrorIndication\n  body: %s", got, resp)
	}
}

// TestUEContextReleaseRequest_CommandCarriesCause confirms the AMF's release
// command carries a Cause IE (decoded into the response).
func Test5GUEContextReleaseRequest_CommandCarriesCause(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
	if got := jsonGet(body, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Fatalf("ngap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}
	if !strings.Contains(string(body), `"cause"`) {
		t.Errorf("expected a decoded cause IE in the release command\n  body: %s", body)
	}
}
