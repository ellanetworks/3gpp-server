// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test5GRegistrationComplete_Fuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantNGAPMsgType string
	}{
		{
			name:     "valid registration_complete (default)",
			body:     `{"message_type":"registration_complete"}`,
			wantHTTP: 200,
		},
		{
			name:            "raw NAS: empty PDU",
			body:            `{"message_type":"registration_complete","raw_nas_pdu":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "raw NAS: garbage bytes",
			body:            `{"message_type":"registration_complete","raw_nas_pdu":"deadbeefcafebabe"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name: "raw NAS: plain RegistrationComplete (no security)",
			// 7E EPD, 00 SHT plain, 43 RegistrationComplete: unprotected under an active
			// security context, so TS 24.501 §4.4.4.3 discards it — no reply.
			body:     `{"message_type":"registration_complete","raw_nas_pdu":"7e0043"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: integrity header with zeroed MAC",
			// 7E 04 integrity-protected new context, MAC=00000000, SQN=00, then 7e0043:
			// integrity fails, so TS 24.501 §4.4.4.3 discards it — no reply.
			body:     `{"message_type":"registration_complete","raw_nas_pdu":"7e0400000000000000007e0043"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: security wrapper with zeroed MAC, wrong inner message type 0xff",
			// SHT=02 integrity+cipher with a zeroed MAC: integrity fails per TS 24.501
			// §4.4.4.3 before the inner message type is reached — no reply.
			body:     `{"message_type":"registration_complete","raw_nas_pdu":"7e02000000000000007e00ff"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: single byte (truncated)",
			// TS 24.501 §7.2.1: too short for a message type IE, so it is ignored — no reply.
			body:     `{"message_type":"registration_complete","raw_nas_pdu":"7e"}`,
			wantHTTP: 504,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGNB(t)
			ueID := mustCreateUE(t, gnbID)

			for _, step := range []string{
				`{"message_type":"registration_request"}`,
				`{"message_type":"authentication_response"}`,
				`{"message_type":"security_mode_complete"}`,
			} {
				status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", step)
				if status != 200 {
					t.Fatalf("setup step failed: HTTP %d\n  body: %s", status, resp)
				}
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
		})
	}

	assertGNBCoreAlive(t)
}

func Test5GRegistrationComplete_NGAPIDFuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantNGAPMsgType string
	}{
		{
			name:            "AMF UE NGAP ID = 0",
			body:            `{"message_type":"registration_complete","amf_ue_ngap_id_override":0}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "AMF UE NGAP ID = nonexistent",
			body:            `{"message_type":"registration_complete","amf_ue_ngap_id_override":99999}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "RAN UE NGAP ID = 0",
			body:            `{"message_type":"registration_complete","ran_ue_ngap_id_override":0}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "RAN UE NGAP ID = max 32-bit",
			body:            `{"message_type":"registration_complete","ran_ue_ngap_id_override":4294967295}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "AMF UE NGAP ID = max valid 40-bit",
			body:            `{"message_type":"registration_complete","amf_ue_ngap_id_override":1099511627775}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGNB(t)
			ueID := mustCreateUE(t, gnbID)

			for _, step := range []string{
				`{"message_type":"registration_request"}`,
				`{"message_type":"authentication_response"}`,
				`{"message_type":"security_mode_complete"}`,
			} {
				status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", step)
				if status != 200 {
					t.Fatalf("setup step failed: HTTP %d\n  body: %s", status, resp)
				}
			}

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tt.body)
			if status != tt.wantHTTP {
				t.Fatalf("HTTP %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}

			if tt.wantNGAPMsgType != "" {
				if got := jsonGet(body, "ngap.message_type"); got != tt.wantNGAPMsgType {
					t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, tt.wantNGAPMsgType, body)
				}

				if tt.wantNGAPMsgType == ngapErrorIndication {
					assertSpecCompliantErrorIndication(t, body)
				}
			}
		})
	}
}
