//go:build integration

package integration_test

import (
	"testing"
)

func TestDeregistration_Fuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantNGAPMsgType string
		wantNASMsgType  string
	}{
		{
			name:     "valid deregistration after full registration + PDU session",
			body:     `{"message_type":"deregistration_request"}`,
			wantHTTP: 200,
		},
		{
			name:     "raw NAS: empty",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":""}`,
			wantHTTP: 200,
		},
		{
			name:     "raw NAS: garbage",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"deadbeefcafebabe"}`,
			wantHTTP: 200,
		},
		{
			name:     "raw NAS: plain deregistration (no security)",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e00450900"}`,
			wantHTTP: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGnB(t)
			ueID := mustCreateUE(t, gnbID)

			doRegistrationFlow(t, gnbID, ueID)

			status, _ := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
				`{"message_type":"pdu_session_establishment_request"}`)
			if status != 200 {
				t.Fatalf("pdu_session: HTTP %d", status)
			}

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tt.body)
			if status != tt.wantHTTP {
				t.Fatalf("HTTP %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}

			if tt.wantHTTP != 200 {
				return
			}

			ngapMsgType := jsonGet(body, "ngap.message_type")
			if tt.wantNGAPMsgType != "" {
				if ngapMsgType != tt.wantNGAPMsgType {
					t.Errorf("ngap.message_type = %q, want %q\n  body: %s", ngapMsgType, tt.wantNGAPMsgType, body)
				}
			}

			if tt.wantNASMsgType != "" {
				if got := jsonGet(body, "nas.message_type"); got != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q\n  body: %s", got, tt.wantNASMsgType, body)
				}
			}
		})
	}
}
