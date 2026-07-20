// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test5GScenarioRegistration(t *testing.T) {
	gnbID := mustCreateGNB(t)

	var ueID string
	supi := claimSubscriber(t)

	t.Run("create UE and verify state", func(t *testing.T) {
		ueID = mustCreateUEWithSUPI(t, gnbID, supi)

		status, body := doRequest(t, "GET", "/gnb/"+gnbID+"/ue/"+ueID, "")
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}
		checks := map[string]string{
			"supi":              supi,
			"dnn":               "internet",
			"protection_scheme": "0",
			"amf_ue_ngap_id":    "0",
		}
		for field, want := range checks {
			if got := jsonGet(body, field); got != want {
				t.Errorf("%s = %q, want %q", field, got, want)
			}
		}
	})

	t.Run("registration triggers authentication", func(t *testing.T) {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"registration_request"}`)
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}

		if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
			t.Fatalf("nas.message_type = %q, want authentication_request", got)
		}
		if jsonGet(body, "nas.rand") == "" || jsonGet(body, "nas.autn") == "" {
			t.Fatal("missing RAND or AUTN")
		}
	})

	t.Run("authentication response triggers security mode command", func(t *testing.T) {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"authentication_response"}`)
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}

		if got := jsonGet(body, "nas.message_type"); got != nasSecurityModeCommand {
			t.Fatalf("nas.message_type = %q, want security_mode_command", got)
		}
		if jsonGet(body, "nas.selected_ciphering_algorithm") == "" {
			t.Error("missing selected_ciphering_algorithm")
		}
		if jsonGet(body, "nas.selected_integrity_algorithm") == "" {
			t.Error("missing selected_integrity_algorithm")
		}
	})

	t.Run("security mode complete triggers registration accept", func(t *testing.T) {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"security_mode_complete"}`)
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}

		if got := jsonGet(body, "ngap.message_type"); got != ngapInitialContextSetupRequest {
			t.Fatalf("ngap.message_type = %q, want InitialContextSetupRequest", got)
		}
		if got := jsonGet(body, "nas.message_type"); got != nasRegistrationAccept {
			t.Fatalf("nas.message_type = %q, want registration_accept", got)
		}
		if jsonGet(body, "nas.guti.5g_tmsi") == "" {
			t.Error("missing GUTI in RegistrationAccept")
		}

		assertRegistrationAcceptTAIList(t, body)
	})

	t.Run("registration complete finishes the procedure", func(t *testing.T) {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"registration_complete"}`)
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}
	})

	t.Run("PDU session establishment", func(t *testing.T) {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"pdu_session_establishment_request"}`)
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}

		if got := jsonGet(body, "ngap.message_type"); got != ngapPDUSessionResourceSetupRequest {
			t.Errorf("ngap.message_type = %q, want PDUSessionResourceSetupRequest", got)
		}
		if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentAccept {
			t.Errorf("nas.inner_nas_message_type = %q, want pdu_session_establishment_accept", got)
		}
		if got := jsonGet(body, "nas.pdu_address"); got == "" {
			t.Error("missing PDU address")
		} else {
			t.Logf("PDU address: %s", got)
		}
	})

	t.Run("deregistration", func(t *testing.T) {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"deregistration_request"}`)
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}
	})

	t.Run("AMF UE NGAP ID stored", func(t *testing.T) {
		status, body := doRequest(t, "GET", "/gnb/"+gnbID+"/ue/"+ueID, "")
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}
		amfID := jsonGet(body, "amf_ue_ngap_id")
		if amfID == "" || amfID == "0" {
			t.Errorf("amf_ue_ngap_id = %q, want non-zero", amfID)
		}
	})

	t.Run("DELETE UE", func(t *testing.T) {
		status, _ := doRequest(t, "DELETE", "/gnb/"+gnbID+"/ue/"+ueID, "")
		if status != 204 {
			t.Fatalf("DELETE HTTP %d, want 204", status)
		}
	})
}
