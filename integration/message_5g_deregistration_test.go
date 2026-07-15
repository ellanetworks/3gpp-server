// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test5GDeregistration_Fuzz(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		wantHTTP         int
		wantNGAPMsgType  string
		wantNASMsgType   string
		wantNASCause5GMM int
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
		{
			// 7E EPD, 00 SHT plain, 45 DeregistrationRequestUEOriginating, 09 = 3GPP
			// access + switch-off, then an empty 5GS mobile identity (TS 24.501 §8.2.12).
			name:     "raw NAS: plain deregistration with switch-off bit set",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e0045090000"}`,
			wantHTTP: 200,
		},
		{
			// 0a = access type 02, non-3GPP.
			name:     "raw NAS: plain deregistration with non-3GPP access type",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e00450a00"}`,
			wantHTTP: 200,
		},
		{
			// 0b = access type 03, both 3GPP and non-3GPP.
			name:     "raw NAS: plain deregistration with both access types",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e00450b00"}`,
			wantHTTP: 200,
		},
		{
			name:     "raw NAS: plain deregistration with re-registration-required",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e0045110000"}`,
			wantHTTP: 200,
		},
		{
			name:     "raw NAS: truncated (missing mobile identity)",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e004509"}`,
			wantHTTP: 200,
		},
		{
			// 7e 00 46 = plain Deregistration accept: TS 24.501 §4.4.4.3 discards it
			// unprotected, before §7.4's unknown-message-type handling — no reply.
			name:     "raw NAS: deregistration accept type (wrong direction, unprotected)",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e0046"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: missing security header (single byte EPD)",
			// TS 24.501 §7.2.1: too short for a message type IE, so it is ignored — no reply.
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e"}`,
			wantHTTP: 504,
		},
		{
			name:            "NGAP override: AMF UE NGAP ID = 0",
			body:            `{"message_type":"deregistration_request","amf_ue_ngap_id_override":0}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "NGAP override: RAN UE NGAP ID = 999999",
			body:            `{"message_type":"deregistration_request","ran_ue_ngap_id_override":999999}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
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

				if tt.wantNGAPMsgType == ngapErrorIndication {
					assertSpecCompliantErrorIndication(t, body)
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
