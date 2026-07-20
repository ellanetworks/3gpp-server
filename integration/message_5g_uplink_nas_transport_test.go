// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test5GUplinkNASTransport_NGAPIDFuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantNGAPMsgType string
	}{
		{
			name:            "AMF UE NGAP ID = 0 (never allocated)",
			body:            `{"message_type":"authentication_response","amf_ue_ngap_id_override":0}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "AMF UE NGAP ID = 99999 (never allocated)",
			body:            `{"message_type":"authentication_response","amf_ue_ngap_id_override":99999}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "RAN UE NGAP ID = 99999 (never allocated)",
			body:            `{"message_type":"authentication_response","ran_ue_ngap_id_override":99999}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "AMF UE NGAP ID = 2^40 - 1 (never allocated, edge of valid range)",
			body:            `{"message_type":"authentication_response","amf_ue_ngap_id_override":1099511627775}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:            "both AMF and RAN UE NGAP IDs forged",
			body:            `{"message_type":"authentication_response","amf_ue_ngap_id_override":99999,"ran_ue_ngap_id_override":99999}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGNB(t)
			ueID := mustCreateUE(t, gnbID)

			status, _ := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
				`{"message_type":"registration_request"}`)
			if status != 200 {
				t.Fatalf("registration_request: HTTP %d", status)
			}

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tt.body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			if got := jsonGet(body, "ngap.message_type"); got != tt.wantNGAPMsgType {
				t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, tt.wantNGAPMsgType, body)
			}

			if tt.wantNGAPMsgType == ngapErrorIndication {
				assertSpecCompliantErrorIndication(t, body)
			}
		})
	}
}
