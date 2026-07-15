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
			// TS 24.501 §8.2.12 — DeregistrationRequestUEOriginating
			// EPD=7E SHT=00 plain, msg type=45, then deregistration-type octet:
			//   access type=01 (3GPP), re-reg=0, switch-off=1 → 0x09
			// followed by an empty Mobile identity (5GS).
			name:     "raw NAS: plain deregistration with switch-off bit set",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e0045090000"}`,
			wantHTTP: 200,
		},
		{
			// access type=02 (non-3GPP) — Ella Core only supports 3GPP access
			name:     "raw NAS: plain deregistration with non-3GPP access type",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e00450a00"}`,
			wantHTTP: 200,
		},
		{
			// access type=03 (both 3GPP + non-3GPP)
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
			// 0x46 = Deregistration accept (UE originating), a downlink type sent
			// uplink, and sent plain: raw_nas_pdu goes on the wire unwrapped. The
			// registration flow has established secure exchange, so TS 24.501
			// §4.4.4.3 governs before §7.4's unknown-message-type handling: "If
			// any NAS signalling message is received, as not integrity protected
			// even though the secure exchange of NAS messages has been
			// established, then the NAS shall discard this message." Discarding
			// without a reply is the mandated outcome.
			name:     "raw NAS: deregistration accept type (wrong direction, unprotected)",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e0046"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: missing security header (single byte EPD)",
			// Too short to carry a complete message type IE, so it shall be
			// ignored (TS 24.501 §7.2.1): no reply is the mandated outcome.
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e"}`,
			wantHTTP: 504,
		},
		{
			// Unknown local AP ID (TS 38.413 §10.6).
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
