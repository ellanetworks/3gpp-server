//go:build integration

package integration_test

import (
	"testing"
)

func TestPDUSessionEstablishment_Fuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantNGAPMsgType string
		wantNASField    string
		wantNASValue    string
	}{
		{
			name:            "valid PDU session establishment",
			body:            `{"message_type":"pdu_session_establishment_request"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "PDUSessionResourceSetupRequest",
			wantNASField:    "inner_nas_message_type",
			wantNASValue:    "pdu_session_establishment_accept",
		},
		{
			name:     "raw NAS: empty PDU",
			body:     `{"message_type":"pdu_session_establishment_request","raw_nas_pdu":""}`,
			wantHTTP: 200,
		},
		{
			name:     "raw NAS: garbage bytes",
			body:     `{"message_type":"pdu_session_establishment_request","raw_nas_pdu":"deadbeefcafebabe"}`,
			wantHTTP: 200,
		},
		{
			name:     "raw NAS: valid 5GMM header but wrong message type",
			body:     `{"message_type":"pdu_session_establishment_request","raw_nas_pdu":"7e00ff"}`,
			wantHTTP: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGnB(t)
			ueID := mustCreateUE(t, gnbID)

			doRegistrationFlow(t, gnbID, ueID)

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tt.body)
			if status != tt.wantHTTP {
				t.Fatalf("HTTP %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}

			if tt.wantHTTP != 200 {
				return
			}

			if tt.wantNGAPMsgType != "" {
				if got := jsonGet(body, "ngap.message_type"); got != tt.wantNGAPMsgType {
					t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, tt.wantNGAPMsgType, body)
				}
			}

			if tt.wantNASField != "" && tt.wantNASValue != "" {
				if got := jsonGet(body, "nas."+tt.wantNASField); got != tt.wantNASValue {
					t.Errorf("nas.%s = %q, want %q\n  body: %s", tt.wantNASField, got, tt.wantNASValue, body)
				}
			}

		})
	}
}
