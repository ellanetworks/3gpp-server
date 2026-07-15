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
			// followed by Mobile identity (5GS).
			// Empty mobile identity → AMF should respond.
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
			// re-registration-required bit set
			name:     "raw NAS: plain deregistration with re-registration-required",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e0045110000"}`,
			wantHTTP: 200,
		},
		{
			// truncated — missing mobile identity octet entirely
			name:     "raw NAS: truncated (missing mobile identity)",
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e004509"}`,
			wantHTTP: 200,
		},
		{
			// 0x46 = DeregistrationAcceptUEOriginating, a downlink type sent
			// uplink. Per TS 24.501 §7.4 NOTE, "a message type not defined for
			// the EPD in the given direction is regarded by the receiver as a
			// message type not defined for the EPD". Reception of an unsolicited
			// 5GMM message from the UE is foreseen, so §7.4's implementation-
			// dependent branch does not apply: the AMF "shall ignore the message
			// except that it should return a status message ... with cause #97
			// 'message type non-existent or not implemented'".
			name:             "raw NAS: deregistration accept type (wrong direction)",
			body:             `{"message_type":"deregistration_request","raw_nas_pdu":"7e0046"}`,
			wantHTTP:         200,
			wantNASMsgType:   nasStatus5GMM,
			wantNASCause5GMM: cause5GMMMessageTypeNonExistent,
		},
		{
			name: "raw NAS: missing security header (single byte EPD)",
			// Too short to contain a complete message type IE → shall be ignored
			// (TS 24.501 §7.2.1). Silent drop is the mandated behaviour (504).
			body:     `{"message_type":"deregistration_request","raw_nas_pdu":"7e"}`,
			wantHTTP: 504,
		},
		{
			// NGAP-level: stale AMF UE NGAP ID — unknown local AP ID (TS 38.413 §10.6)
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
