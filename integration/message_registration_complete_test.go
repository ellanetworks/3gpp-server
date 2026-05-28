//go:build integration

// Tests for RegistrationComplete (TS 24.501 §8.2.8). The message is the
// fourth step of initial registration; the AMF expects it after sending
// Registration Accept. Until it arrives, the AMF retransmits Registration
// Accept on a T3550 timer and the 5GMM context is still in REGISTERED-
// INITIATED state.
//
// Tests cover:
//   - raw NAS fuzz: malformed RegistrationComplete payloads that should not
//     crash the AMF and should leave it free to retransmit/timeout cleanly
//   - NGAP-ID overrides: AMF/RAN UE NGAP ID mutations on the carrying
//     UL NAS TRANSPORT

package integration_test

import (
	"testing"
)

func TestRegistrationComplete_Fuzz(t *testing.T) {
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
			wantNGAPMsgType: "ErrorIndication",
		},
		{
			name:            "raw NAS: garbage bytes",
			body:            `{"message_type":"registration_complete","raw_nas_pdu":"deadbeefcafebabe"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			// Garbage 5GMM payload → AMF rejects with 5GMM STATUS
		},
		{
			name: "raw NAS: plain RegistrationComplete (no security)",
			// 7E EPD, 00 SHT plain, 43 msg type = RegistrationComplete
			// TS 24.501 §4.4.4.3 — only specific plain NAS types allowed
			// when a security context is active; RegistrationComplete is NOT
			// in the whitelist, so AMF should reject.
			body:            `{"message_type":"registration_complete","raw_nas_pdu":"7e0043"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "raw NAS: integrity header with zeroed MAC",
			// 7E 04 (integrity protected, new context) MAC=0000000000 SQN=00 then 7e0043
			body:            `{"message_type":"registration_complete","raw_nas_pdu":"7e0400000000000000007e0043"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "raw NAS: valid security wrapper but wrong inner message type 0xff",
			// SHT=02 integrity+cipher, then wrong msg type inside
			body:            `{"message_type":"registration_complete","raw_nas_pdu":"7e02000000000000007e00ff"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "raw NAS: single byte (truncated)",
			body:            `{"message_type":"registration_complete","raw_nas_pdu":"7e"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			// Truncated → AMF should respond, not silently drop
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGnB(t)
			ueID := mustCreateUE(t, gnbID)

			// Run the three steps before RegistrationComplete.
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
}

// TestRegistrationComplete_NGAPIDFuzz exercises NGAP-level ID mutations on
// the UL NAS TRANSPORT that carries RegistrationComplete. AMF must reject /
// ignore mismatched IDs without crashing, per TS 38.413 §8.6.2.
func TestRegistrationComplete_NGAPIDFuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantNGAPMsgType string
	}{
		{
			name:     "AMF UE NGAP ID = 0",
			body:     `{"message_type":"registration_complete","amf_ue_ngap_id_override":0}`,
			wantHTTP: 200,
			// AMF accepts (treats as unknown context + processes)
		},
		{
			name:     "AMF UE NGAP ID = nonexistent",
			body:     `{"message_type":"registration_complete","amf_ue_ngap_id_override":99999}`,
			wantHTTP: 200,
		},
		{
			name:            "RAN UE NGAP ID = 0",
			body:            `{"message_type":"registration_complete","ran_ue_ngap_id_override":0}`,
			wantHTTP:        200,
			wantNGAPMsgType: "ErrorIndication",
			// TS 38.413 §8.6.2 — wrong RAN UE NGAP ID → ErrorIndication
		},
		{
			name:            "RAN UE NGAP ID = max 32-bit",
			body:            `{"message_type":"registration_complete","ran_ue_ngap_id_override":4294967295}`,
			wantHTTP:        200,
			wantNGAPMsgType: "ErrorIndication",
		},
		{
			name:     "AMF UE NGAP ID = max valid 40-bit",
			body:     `{"message_type":"registration_complete","amf_ue_ngap_id_override":1099511627775}`,
			wantHTTP: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGnB(t)
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
			}
		})
	}
}
