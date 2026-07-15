// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Cross-fuzz tests: simultaneously mutate the NGAP-level IDs of the
// UplinkNASTransport (AMF UE NGAP ID, RAN UE NGAP ID) AND the carried
// NAS payload. Goal is to surface AMF code paths where the NGAP check
// and the NAS decode interact — e.g. dropping the message vs. emitting
// ErrorIndication vs. emitting STATUS_5GMM.

package integration_test

import (
	"testing"
)

// Test5GULNasTransport_CrossFuzz combines NGAP-ID overrides with malformed
// inner NAS PDUs. Per TS 38.413 §8.7.5.2 the NGAP-level UE ID check happens
// before the AMF looks at the NAS payload, so whenever at least one of the
// AMF UE NGAP ID / RAN UE NGAP ID is wrong the AMF must respond with
// ErrorIndication regardless of what the NAS PDU contains.
func Test5GULNasTransport_CrossFuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantNGAPMsgType string
	}{
		{
			name: "stale AMF UE NGAP ID + valid NAS",
			body: `{
				"message_type":"authentication_response",
				"amf_ue_ngap_id_override":99999
			}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name: "zero RAN UE NGAP ID + garbage NAS",
			body: `{
				"message_type":"authentication_response",
				"ran_ue_ngap_id_override":0,
				"raw_nas_pdu":"deadbeefcafebabe"
			}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name: "stale RAN UE NGAP ID + empty NAS",
			body: `{
				"message_type":"authentication_response",
				"ran_ue_ngap_id_override":999999,
				"raw_nas_pdu":""
			}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name: "both IDs zero + plain NAS",
			body: `{
				"message_type":"authentication_response",
				"amf_ue_ngap_id_override":0,
				"ran_ue_ngap_id_override":0,
				"raw_nas_pdu":"7e005700"
			}`,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name: "max IDs + truncated NAS",
			body: `{
				"message_type":"authentication_response",
				"amf_ue_ngap_id_override":1099511627775,
				"ran_ue_ngap_id_override":4294967295,
				"raw_nas_pdu":"7e"
			}`,
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
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			if got := jsonGet(body, "ngap.message_type"); got != tt.wantNGAPMsgType {
				t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, tt.wantNGAPMsgType, body)
			}
		})
	}
}
