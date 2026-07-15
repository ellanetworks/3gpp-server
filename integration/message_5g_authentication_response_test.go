// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test5GAuthenticationResponse(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		wantHTTP         int
		wantNGAPMsgType  string
		wantNASMsgType   string
		wantNASCause5GMM int
	}{
		{
			name:            "correct RES* (happy path)",
			body:            `{"message_type":"authentication_response"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasSecurityModeCommand,
		},
		{
			// RES* mismatch for a SUCI-identified UE: the AMF aborts
			// authentication with Authentication Reject (TS 33.501 §6.1.3.2.2).
			name:            "wrong RES*: 16 bytes of zeros",
			body:            `{"message_type":"authentication_response","res_star_override":"00000000000000000000000000000000"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationReject,
		},
		{
			name:            "wrong RES*: 16 bytes of 0xff",
			body:            `{"message_type":"authentication_response","res_star_override":"ffffffffffffffffffffffffffffffff"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationReject,
		},
		{
			// 32 bytes still decode as a 16-octet RES* that mismatches → reject.
			name:            "oversized RES*: 32 bytes",
			body:            `{"message_type":"authentication_response","res_star_override":"0000000000000000000000000000000000000000000000000000000000000000"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationReject,
		},
		{
			// With the Authentication response parameter IE omitted there is no
			// RES* to verify, so the AMF rejects authentication (TS 24.501
			// §5.4.1.3.5).
			name:            "empty RES*",
			body:            `{"message_type":"authentication_response","res_star_override":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationReject,
		},
		{
			name:            "raw NAS PDU: valid AuthResponse structure with garbage RES*",
			body:            `{"message_type":"authentication_response","raw_nas_pdu":"7e00572d10deadbeefcafebabe0011223344556677"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationReject,
		},
		{
			name: "raw NAS PDU: single byte",
			// Too short to carry a complete message type IE, so it shall be ignored
			// (TS 24.501 §7.2.1): the AMF keeps T3560 running and sends no reply.
			body:     `{"message_type":"authentication_response","raw_nas_pdu":"7e"}`,
			wantHTTP: 504,
		},
		{
			name:            "raw NAS PDU: empty → ErrorIndication",
			body:            `{"message_type":"authentication_response","raw_nas_pdu":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
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

			assertNASCause(t, body, "nas.cause_5gmm", tt.wantNASCause5GMM)
		})
	}
}

// An Authentication Response sent before any challenge has no stored RAND/AUTN
// to answer. The server must still put it on the wire with a zeroed RES* so the
// AMF is the one that reacts to it.
func Test5GAuthenticationResponse_WithoutChallenge(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"authentication_response"}`)
	if status == 504 {
		t.Fatalf("authentication response hung (HTTP 504) — message may not have reached the AMF\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200 (message must reach the AMF, not be refused locally)\n  body: %s", status, body)
	}
}

// An 8-octet RES* is a syntactically incorrect mandatory IE (TS 24.501
// §9.11.3.17 fixes RES* at 16 octets). TS 24.501 §7.5.1 lets the network
// "either: 1) try to treat the
// message (the exact further actions are implementation dependent); or 2) ignore
// the message except that it should return a status message ... with cause #96
// 'invalid mandatory information'." Option 1 leaves the treatment open, so the
// message type is not pinned; #96 is the only cause the clause names for a
// status answering this message.
func Test5GAuthenticationResponse_TruncatedRESStar(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	if status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request"}`); status != 200 {
		t.Fatalf("registration_request: HTTP %d\n  body: %s", status, body)
	}

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"authentication_response","res_star_override":"0000000000000000"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200 — a syntactically incorrect mandatory IE must draw a reply (TS 24.501 §7.5.1)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got == nasStatus5GMM {
		assertNASCause(t, body, "nas.cause_5gmm", cause5GMMInvalidMandatoryInformation)
	}
}
