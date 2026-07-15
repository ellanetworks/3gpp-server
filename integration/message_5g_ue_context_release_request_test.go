// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"strings"
	"testing"
)

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

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request","registration_type":2}`)
	if status != 200 {
		t.Fatalf("re-register: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasRegistrationAccept {
		t.Errorf("re-register nas.message_type = %q, want registration_accept\n  body: %s", got, body)
	}
}

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

// The Cause IE is informational, so an out-of-range value leaves the AMF free to
// process the request or to reject the encoding.
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
