// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test5GSecurityModeComplete_NGAPIDFuzz(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unknown AMF UE NGAP ID", `{"message_type":"security_mode_complete","amf_ue_ngap_id_override":99999}`},
		{"inconsistent RAN UE NGAP ID", `{"message_type":"security_mode_complete","ran_ue_ngap_id_override":99999}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gnbID, ueID := securityModePending(t)

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tc.body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			assertSpecCompliantErrorIndication(t, body)
		})
	}
}

func Test5GSecurityModeComplete_Fuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantNGAPMsgType string
		wantNASMsgType  string
		wantCause5GMM   int
	}{
		{
			name: "raw NAS: plain SecurityModeComplete (no integrity protection)",
			// 7E EPD, 00 SHT plain, 5e SecurityModeComplete: TS 24.501 §4.4.4.3 discards
			// it unprotected — no reply.
			body:     `{"message_type":"security_mode_complete","raw_nas_pdu":"7e005e00"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: integrity header but zeroed MAC",
			// 7E 04 integrity-protected new context, zeroed MAC: integrity fails, so
			// TS 24.501 §4.4.4.3 discards it — no reply.
			body:     `{"message_type":"security_mode_complete","raw_nas_pdu":"7e04000000000000005e00"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: security header claiming ciphering, zeroed MAC",
			// SHT=02 integrity+cipher with a zeroed MAC: TS 24.501 §4.4.4.3 discards it — no reply.
			body:     `{"message_type":"security_mode_complete","raw_nas_pdu":"7e02000000000000005e00"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: single byte",
			// TS 24.501 §7.2.1: too short for a message type IE, so it is ignored — no reply.
			body:     `{"message_type":"security_mode_complete","raw_nas_pdu":"7e"}`,
			wantHTTP: 504,
		},
		{
			name:            "raw NAS: empty → ErrorIndication",
			body:            `{"message_type":"security_mode_complete","raw_nas_pdu":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "raw NAS: garbage bytes",
			body:            `{"message_type":"security_mode_complete","raw_nas_pdu":"deadbeefcafebabe0011223344556677"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			// TS 24.501 §7.4: reception of a 5GMM message is foreseen in this state, so
			// the AMF should answer an undefined message type with 5GMM STATUS and #97.
			name:            "raw NAS: valid NAS header but unknown message type 0xff",
			body:            `{"message_type":"security_mode_complete","raw_nas_pdu":"7e00ff"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasStatus5GMM,
			wantCause5GMM:   cause5GMMMessageTypeNonExistent,
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

			status, _ = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
				`{"message_type":"authentication_response"}`)
			if status != 200 {
				t.Fatalf("authentication_response: HTTP %d", status)
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

			assertNASCause(t, body, "nas.cause_5gmm", tt.wantCause5GMM)

			ngapMsgType := jsonGet(body, "ngap.message_type")
			if ngapMsgType != ngapErrorIndication {
				nasMsgType := jsonGet(body, "nas.message_type")
				if nasMsgType == "" {
					nasMsgType = jsonGet(body, "nas.security_header_type")
				}

				if nasMsgType == "" {
					t.Errorf("AMF did not return a decodable NAS response\n  body: %s", body)
				}
			}
		})
	}
}
