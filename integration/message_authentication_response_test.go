//go:build integration

package integration_test

import (
	"testing"
)

func TestAuthenticationResponse(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantNGAPMsgType string
		wantNASMsgType  string
	}{
		{
			name:            "correct RES* (happy path)",
			body:            `{"message_type":"authentication_response"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "security_mode_command",
		},
		{
			name:            "wrong RES*: 16 bytes of zeros",
			body:            `{"message_type":"authentication_response","res_star_override":"00000000000000000000000000000000"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name:            "wrong RES*: 16 bytes of 0xff",
			body:            `{"message_type":"authentication_response","res_star_override":"ffffffffffffffffffffffffffffffff"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name:            "truncated RES*: 8 bytes",
			body:            `{"message_type":"authentication_response","res_star_override":"0000000000000000"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "status_5gmm",
		},
		{
			name:            "oversized RES*: 32 bytes",
			body:            `{"message_type":"authentication_response","res_star_override":"0000000000000000000000000000000000000000000000000000000000000000"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name:            "empty RES*",
			body:            `{"message_type":"authentication_response","res_star_override":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "raw NAS PDU: valid AuthResponse structure with garbage RES*",
			body: `{"message_type":"authentication_response","raw_nas_pdu":"7e00572d10deadbeefcafebabe0011223344556677"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name:            "raw NAS PDU: single byte",
			body:            `{"message_type":"authentication_response","raw_nas_pdu":"7e"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name:            "raw NAS PDU: empty → ErrorIndication",
			body:            `{"message_type":"authentication_response","raw_nas_pdu":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: "ErrorIndication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGnB(t)
			ueID := mustCreateUE(t, gnbID)

			status, _ := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
				`{"message_type":"registration_request"}`)
			if status != 200 {
				t.Fatalf("registration_request: HTTP %d", status)
			}

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

			if tt.wantNASMsgType != "" {
				if got := jsonGet(body, "nas.message_type"); got != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q\n  body: %s", got, tt.wantNASMsgType, body)
				}
			}
		})
	}
}
