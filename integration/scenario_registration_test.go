//go:build integration

// Scenario tests exercise multi-step 5G procedures end to end.
// Unlike message tests (which verify individual NGAP messages in isolation),
// scenario tests care about state transitions across steps.

package integration_test

import (
	"strings"
	"testing"
)

func TestScenarioRegistration(t *testing.T) {
	gnbID := mustCreateGnB(t)

	var ueID string
	t.Run("create UE and verify state", func(t *testing.T) {
		ueID = mustCreateUE(t, gnbID)

		status, body := doRequest(t, "GET", "/gnb/"+gnbID+"/ue/"+ueID, "")
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}
		checks := map[string]string{
			"supi":              "imsi-001010000000001",
			"mcc":               "001",
			"mnc":               "01",
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

		if got := jsonGet(body, "nas.message_type"); got != "authentication_request" {
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

		if got := jsonGet(body, "nas.message_type"); got != "security_mode_command" {
			t.Fatalf("nas.message_type = %q, want security_mode_command", got)
		}
		if jsonGet(body, "nas.selected_ciphering_alg") == "" {
			t.Error("missing selected_ciphering_alg")
		}
		if jsonGet(body, "nas.selected_integrity_alg") == "" {
			t.Error("missing selected_integrity_alg")
		}
	})

	t.Run("security mode complete triggers registration accept", func(t *testing.T) {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"security_mode_complete"}`)
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}

		if got := jsonGet(body, "ngap.message_type"); got != "InitialContextSetupRequest" {
			t.Fatalf("ngap.message_type = %q, want InitialContextSetupRequest", got)
		}
		if got := jsonGet(body, "nas.message_type"); got != "registration_accept" {
			t.Fatalf("nas.message_type = %q, want registration_accept", got)
		}
		if jsonGet(body, "nas.guti") == "" {
			t.Error("missing GUTI in RegistrationAccept")
		}
	})

	t.Run("registration complete finishes the procedure", func(t *testing.T) {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"registration_complete"}`)
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

func TestUEErrorPaths(t *testing.T) {
	gnbID := mustCreateGnB(t)

	tests := []struct {
		name     string
		method   string
		path     string
		body     string
		wantHTTP int
	}{
		{
			name:     "create UE missing SUPI",
			method:   "POST",
			path:     "/gnb/{gnb}/ue",
			body:     `{"k":"00112233445566778899aabbccddeeff","opc":"63bfa50ee6523365ff14c1f45f88737d"}`,
			wantHTTP: 400,
		},
		{
			name:     "create UE missing K",
			method:   "POST",
			path:     "/gnb/{gnb}/ue",
			body:     `{"supi":"imsi-001010000000001","opc":"63bfa50ee6523365ff14c1f45f88737d"}`,
			wantHTTP: 400,
		},
		{
			name:     "get non-existent UE",
			method:   "GET",
			path:     "/gnb/{gnb}/ue/999",
			wantHTTP: 404,
		},
		{
			name:     "delete non-existent UE",
			method:   "DELETE",
			path:     "/gnb/{gnb}/ue/999",
			wantHTTP: 404,
		},
		{
			name:     "send NGAP for non-existent UE",
			method:   "POST",
			path:     "/gnb/{gnb}/ue/999/ngap",
			body:     `{"message_type":"registration_request"}`,
			wantHTTP: 404,
		},
		{
			name:     "UE on non-existent gNB",
			method:   "GET",
			path:     "/gnb/999/ue/1",
			wantHTTP: 404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := strings.ReplaceAll(tt.path, "{gnb}", gnbID)
			status, body := doRequest(t, tt.method, path, tt.body)
			if status != tt.wantHTTP {
				t.Errorf("HTTP %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}
		})
	}
}
