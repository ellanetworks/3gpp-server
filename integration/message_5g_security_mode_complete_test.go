// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// A wrong UE NGAP ID must draw an Error Indication (TS 38.413 §10.6, §8.7.5.2).
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
	}{
		{
			name: "raw NAS: plain SecurityModeComplete (no integrity protection)",
			// SECURITY MODE COMPLETE must be integrity protected with the new context
			// and is not in the TS 24.501 §4.4.4.3 exempt list, so a plain one fails
			// the integrity requirement and shall be discarded: the AMF keeps T3560
			// running and sends no reply.
			body:     `{"message_type":"security_mode_complete","raw_nas_pdu":"7e005e00"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: integrity header but zeroed MAC",
			// The zeroed MAC fails the integrity check, so it is discarded per
			// TS 24.501 §4.4.4.3: the AMF must not act on unauthenticated NAS.
			body:     `{"message_type":"security_mode_complete","raw_nas_pdu":"7e04000000000000005e00"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: security header claiming ciphering, zeroed MAC",
			// Claims integrity+ciphering but carries a zeroed MAC, so the integrity
			// check fails and it is discarded per TS 24.501 §4.4.4.3.
			body:     `{"message_type":"security_mode_complete","raw_nas_pdu":"7e02000000000000005e00"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: single byte",
			// Too short to carry a complete message type IE, so it shall be
			// ignored (TS 24.501 §7.2.1): no reply is the mandated outcome.
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
			name:            "raw NAS: valid NAS header but unknown message type 0xff",
			body:            `{"message_type":"security_mode_complete","raw_nas_pdu":"7e00ff"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
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
