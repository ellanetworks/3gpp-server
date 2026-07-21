// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// Test4GAttachRequest_Fuzz is the 4G twin of Test5GInitialUEMessage_Fuzz: it
// carries mutated NAS bytes in the InitialUEMessage via raw_nas_pdu on the
// attach_request. The MME must never accept a malformed PDU as an attach, and a
// PDU whose EMM header identifies an ATTACH REQUEST must draw an ATTACH REJECT
// (TS 24.301 §5.5.1.2.7 b).
func Test4GAttachRequest_Fuzz(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantNASMsgType string
		assertReject   bool
	}{
		{
			name:           "valid attach draws EPS-AKA challenge",
			body:           `{"message_type":"attach_request"}`,
			wantNASMsgType: "authentication_request",
		},
		{
			name: "raw NAS: empty PDU",
			body: `{"message_type":"attach_request","raw_nas_pdu":"","timeout_ms":1000}`,
		},
		{
			name: "raw NAS: garbage bytes",
			body: `{"message_type":"attach_request","raw_nas_pdu":"deadbeefcafebabe","timeout_ms":1000}`,
		},
		{
			// A lone EMM header octet is too short for a message type (TS 24.301 §7.2).
			name: "raw NAS: single EMM header byte",
			body: `{"message_type":"attach_request","raw_nas_pdu":"07","timeout_ms":1000}`,
		},
		{
			// 07 plain EMM header, 00 is not an assigned message type (TS 24.301 §9.8).
			name: "raw NAS: plain header with message type 0x00",
			body: `{"message_type":"attach_request","raw_nas_pdu":"0700","timeout_ms":1000}`,
		},
		{
			// 07 plain EMM header, ff is not an assigned message type (TS 24.301 §9.8).
			name: "raw NAS: plain header with undefined message type 0xff",
			body: `{"message_type":"attach_request","raw_nas_pdu":"07ff","timeout_ms":1000}`,
		},
		{
			// 07 plain EMM header, 41 ATTACH REQUEST, no message body.
			name:         "raw NAS: attach request header, no body",
			body:         `{"message_type":"attach_request","raw_nas_pdu":"0741","timeout_ms":3000}`,
			assertReject: true,
		},
		{
			// 07 41 ATTACH REQUEST followed by garbage where mandatory IEs belong.
			name:         "raw NAS: attach request header with garbage body",
			body:         `{"message_type":"attach_request","raw_nas_pdu":"0741ffffff00","timeout_ms":3000}`,
			assertReject: true,
		},
		{
			name: "raw NAS: 128 bytes of 0xff",
			body: `{"message_type":"attach_request","raw_nas_pdu":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","timeout_ms":1000}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID := mustCreateENBUE(t, enbID)

			status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", tt.body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			if got := jsonGet(body, "nas.message_type"); got == "attach_accept" {
				t.Fatalf("MME accepted a mutated attach request as an attach; body: %s", body)
			}

			if tt.wantNASMsgType != "" {
				if got := jsonGet(body, "nas.message_type"); got != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q\n  body: %s", got, tt.wantNASMsgType, body)
				}
			}

			if tt.assertReject {
				if got := jsonGet(body, "nas.message_type"); got != "attach_reject" {
					t.Errorf("nas.message_type = %q, want attach_reject (TS 24.301 §5.5.1.2.7 b)\n  body: %s", got, body)
				} else if c := jsonGet(body, "nas.emm_cause"); !attachRejectCauseAllowed(c) {
					t.Errorf("attach_reject emm_cause = %q, want 96, 99, 100 or 111 (TS 24.301 §5.5.1.2.7 b)\n  body: %s", c, body)
				}
			}
		})
	}

	assertENBCoreAlive(t)
}

// Test4GAttachComplete_Fuzz is the 4G twin of Test5GRegistrationComplete_Fuzz:
// after the UE reaches ATTACH ACCEPT it sends mutated NAS bytes under the
// attach_complete message type via raw_nas_pdu. An unprotected or malformed PDU
// fails integrity under the active EPS security context (TS 24.301 §4.4.4.3); the
// MME must not crash, and a fresh attach must still complete afterward.
func Test4GAttachComplete_Fuzz(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "raw NAS: empty PDU",
			body: `{"message_type":"attach_complete","raw_nas_pdu":"","timeout_ms":1500}`,
		},
		{
			name: "raw NAS: garbage bytes",
			body: `{"message_type":"attach_complete","raw_nas_pdu":"deadbeefcafebabe","timeout_ms":1500}`,
		},
		{
			// 07 plain EMM header, 43 ATTACH COMPLETE, unprotected under an active context.
			name: "raw NAS: plain attach complete, no integrity",
			body: `{"message_type":"attach_complete","raw_nas_pdu":"0743","timeout_ms":1500}`,
		},
		{
			// 27 integrity-protected-and-ciphered EMM header, zeroed MAC, then 07 43.
			name: "raw NAS: integrity header with zeroed MAC",
			body: `{"message_type":"attach_complete","raw_nas_pdu":"2700000000000743","timeout_ms":1500}`,
		},
		{
			// TS 24.501/24.301 §7.2: a lone header octet is too short for a message type.
			name: "raw NAS: single EMM header byte",
			body: `{"message_type":"attach_complete","raw_nas_pdu":"07","timeout_ms":1500}`,
		},
		{
			name: "raw NAS: plain header, undefined message type 0xff",
			body: `{"message_type":"attach_complete","raw_nas_pdu":"07ff","timeout_ms":1500}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID := mustCreateENBUE(t, enbID)

			if got := jsonGet(nasStep(t, enbID, ueID, "attach_request"), "nas.message_type"); got != "authentication_request" {
				t.Fatalf("attach_request: nas.message_type = %q, want authentication_request", got)
			}
			if got := jsonGet(nasStep(t, enbID, ueID, "authentication_response"), "nas.message_type"); got != "security_mode_command" {
				t.Fatalf("authentication_response: nas.message_type = %q, want security_mode_command", got)
			}
			if got := jsonGet(nasStep(t, enbID, ueID, "security_mode_complete"), "nas.message_type"); got != "attach_accept" {
				t.Fatalf("security_mode_complete: nas.message_type = %q, want attach_accept", got)
			}

			status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", tt.body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}
		})
	}

	assertENBCoreAlive(t)
}

// Test4GSecurityModeComplete_Fuzz is the 4G twin of Test5GSecurityModeComplete_Fuzz:
// after the SECURITY MODE COMMAND it sends mutated NAS bytes under the
// security_mode_complete message type via raw_nas_pdu. An unprotected or bad-MAC
// PDU fails integrity (TS 24.301 §4.4.4.3), so the MME discards it with no reply
// (the handler times out, 504) and must never complete the context by answering
// an Initial Context Setup Request.
func Test4GSecurityModeComplete_Fuzz(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "raw NAS: empty PDU",
			body: `{"message_type":"security_mode_complete","raw_nas_pdu":"","timeout_ms":1500}`,
		},
		{
			name: "raw NAS: garbage bytes",
			body: `{"message_type":"security_mode_complete","raw_nas_pdu":"deadbeefcafebabe0011223344556677","timeout_ms":1500}`,
		},
		{
			// 07 plain EMM header, 5e SECURITY MODE COMPLETE, unprotected.
			name: "raw NAS: plain security mode complete, no integrity",
			body: `{"message_type":"security_mode_complete","raw_nas_pdu":"075e00","timeout_ms":1500}`,
		},
		{
			// 27 integrity-protected-and-ciphered EMM header, zeroed MAC, then 07 5e.
			name: "raw NAS: integrity header with zeroed MAC",
			body: `{"message_type":"security_mode_complete","raw_nas_pdu":"270000000000075e00","timeout_ms":1500}`,
		},
		{
			// 17 integrity-protected EMM header, zeroed MAC, then 07 5e.
			name: "raw NAS: integrity-only header with zeroed MAC",
			body: `{"message_type":"security_mode_complete","raw_nas_pdu":"170000000000075e00","timeout_ms":1500}`,
		},
		{
			name: "raw NAS: single EMM header byte",
			body: `{"message_type":"security_mode_complete","raw_nas_pdu":"07","timeout_ms":1500}`,
		},
		{
			name: "raw NAS: plain header, undefined message type 0xff",
			body: `{"message_type":"security_mode_complete","raw_nas_pdu":"07ff","timeout_ms":1500}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID := mustCreateENBUE(t, enbID)

			if got := jsonGet(nasStep(t, enbID, ueID, "attach_request"), "nas.message_type"); got != "authentication_request" {
				t.Fatalf("attach_request: nas.message_type = %q, want authentication_request", got)
			}
			if got := jsonGet(nasStep(t, enbID, ueID, "authentication_response"), "nas.message_type"); got != "security_mode_command" {
				t.Fatalf("authentication_response: nas.message_type = %q, want security_mode_command", got)
			}

			status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", tt.body)
			if status != 200 && status != 504 {
				t.Fatalf("HTTP %d, want 200 or 504\n  body: %s", status, body)
			}

			if status == 200 && jsonGet(body, "s1ap.message_type") == "InitialContextSetupRequest" {
				t.Fatalf("MME completed the security context on a mutated Security Mode Complete (TS 24.301 §4.4.4.3); body: %s", body)
			}
		})
	}

	assertENBCoreAlive(t)
}

// Test4GServiceRequest_Fuzz is the 4G twin of Test5GServiceRequest_Fuzz: from an
// idle registered UE it re-establishes with mutated SERVICE REQUEST bytes under
// the service_request message type via raw_nas_pdu. A short-MAC failure (TS 24.301
// §5.6.1.5) or garbage must not draw a re-establishment (Initial Context Setup
// Request), and the request must not hang.
func Test4GServiceRequest_Fuzz(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "raw NAS: empty PDU",
			body: `{"message_type":"service_request","raw_nas_pdu":"","timeout_ms":1500}`,
		},
		{
			name: "raw NAS: garbage bytes",
			body: `{"message_type":"service_request","raw_nas_pdu":"deadbeefcafebabe","timeout_ms":1500}`,
		},
		{
			// c7 SERVICE REQUEST security header (SHT 12, EMM PD), KSI/seq 00, zeroed short MAC.
			name: "raw NAS: service request with zeroed short MAC",
			body: `{"message_type":"service_request","raw_nas_pdu":"c7000000","timeout_ms":1500}`,
		},
		{
			// c7 SERVICE REQUEST header truncated before the short MAC.
			name: "raw NAS: truncated service request",
			body: `{"message_type":"service_request","raw_nas_pdu":"c7","timeout_ms":1500}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID := mustCreateENBUE(t, enbID)

			fullAttach(t, enbID, ueID)

			idle := nasStep(t, enbID, ueID, "release_request")
			if got := jsonGet(idle, "s1ap.message_type"); got != "UEContextReleaseCommand" {
				t.Fatalf("release_request: s1ap.message_type = %q, want UEContextReleaseCommand; body: %s", got, idle)
			}

			status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", tt.body)
			if status == 504 {
				t.Fatalf("service request hung (HTTP 504)\n  body: %s", body)
			}
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			if got := jsonGet(body, "s1ap.message_type"); got == "InitialContextSetupRequest" {
				t.Fatalf("MME re-established on a mutated Service Request (TS 24.301 §5.6.1.5); body: %s", body)
			}
		})
	}

	assertENBCoreAlive(t)
}
