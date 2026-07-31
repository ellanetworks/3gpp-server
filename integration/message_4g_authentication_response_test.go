// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func Test4GAuthenticationResponse(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantS1APMsgType string
		wantNASMsgType  string
		wantNASCauseEMM int
		mustNotAuth     bool
	}{
		{
			name:            "correct RES (happy path)",
			body:            `{"message_type":"authentication_response"}`,
			wantHTTP:        200,
			wantS1APMsgType: "DownlinkNASTransport",
			wantNASMsgType:  nasSecurityModeCommand,
		},
		{
			name:            "wrong RES: 8 bytes of zeros",
			body:            `{"message_type":"authentication_response","res_override":"0000000000000000"}`,
			wantHTTP:        200,
			wantS1APMsgType: "DownlinkNASTransport",
			wantNASMsgType:  nasAuthenticationReject,
		},
		{
			name:            "wrong RES: 8 bytes of 0xff",
			body:            `{"message_type":"authentication_response","res_override":"ffffffffffffffff"}`,
			wantHTTP:        200,
			wantS1APMsgType: "DownlinkNASTransport",
			wantNASMsgType:  nasAuthenticationReject,
		},
		{
			// EPS RES is variable-length (TS 24.301 §9.9.3.4, 4–16 octets), so an oversized
			// value is a malformed mandatory IE, not a mismatching RES; the network's
			// rejection mechanism is unspecified (§7.7.2). Only "must not authenticate the
			// UE" is spec-mandated — unlike 5G, whose fixed 16-octet RES* truncates to a
			// valid mismatching value.
			name:        "oversized RES: 32 bytes",
			body:        `{"message_type":"authentication_response","res_override":"0000000000000000000000000000000000000000000000000000000000000000"}`,
			mustNotAuth: true,
		},
		{
			// A zero-length RES is below the IE minimum (TS 24.301 §9.9.3.4): a malformed
			// mandatory IE whose rejection mechanism the network chooses (§7.7.2).
			name:        "empty RES",
			body:        `{"message_type":"authentication_response","res_override":""}`,
			mustNotAuth: true,
		},
		{
			name:            "raw NAS PDU: valid AuthResponse structure with garbage RES",
			body:            `{"message_type":"authentication_response","raw_nas_pdu":"075308deadbeefcafebabe"}`,
			wantHTTP:        200,
			wantS1APMsgType: "DownlinkNASTransport",
			wantNASMsgType:  nasAuthenticationReject,
		},
		{
			// TS 24.301 §7.2: too short for a message type IE, so the MME ignores it — no reply.
			name:     "raw NAS PDU: single byte",
			body:     `{"message_type":"authentication_response","raw_nas_pdu":"07","timeout_ms":2000}`,
			wantHTTP: 504,
		},
		{
			// TS 24.301 §7.2: an empty NAS message is ignored — no reply.
			name:     "raw NAS PDU: empty",
			body:     `{"message_type":"authentication_response","raw_nas_pdu":"","timeout_ms":2000}`,
			wantHTTP: 504,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID := attachChallenge(t, enbID)

			status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", tt.body)

			if tt.mustNotAuth {
				switch status {
				case 200:
					if got := jsonGet(body, "nas.message_type"); got == nasSecurityModeCommand {
						t.Errorf("malformed RES authenticated the UE: nas.message_type = %q\n  body: %s", got, body)
					}
				case 504:
				default:
					t.Fatalf("HTTP %d, want 200 (rejected) or 504 (ignored)\n  body: %s", status, body)
				}

				return
			}

			if status != tt.wantHTTP {
				t.Fatalf("HTTP %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}

			if tt.wantHTTP != 200 {
				return
			}

			if tt.wantS1APMsgType != "" {
				if got := jsonGet(body, "s1ap.message_type"); got != tt.wantS1APMsgType {
					t.Errorf("s1ap.message_type = %q, want %q\n  body: %s", got, tt.wantS1APMsgType, body)
				}
			}

			if tt.wantNASMsgType != "" {
				if got := jsonGet(body, "nas.message_type"); got != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q\n  body: %s", got, tt.wantNASMsgType, body)
				}
			}

			assertNASCause(t, body, "nas.emm_cause", tt.wantNASCauseEMM)
		})
	}

	assertENBCoreAlive(t)
}
