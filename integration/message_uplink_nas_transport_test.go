//go:build integration

package integration_test

import (
	"testing"
)

func TestUplinkNASTransport_NGAPIDFuzz(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantHTTP int
	}{
		{
			name:     "AMF UE NGAP ID set to zero",
			body:     `{"message_type":"authentication_response","amf_ue_ngap_id_override":0}`,
			wantHTTP: 200,
		},
		{
			name:     "AMF UE NGAP ID set to non-existent value",
			body:     `{"message_type":"authentication_response","amf_ue_ngap_id_override":99999}`,
			wantHTTP: 200,
		},
		{
			name:     "RAN UE NGAP ID mismatched",
			body:     `{"message_type":"authentication_response","ran_ue_ngap_id_override":99999}`,
			wantHTTP: 200,
			// AMF should respond (ErrorIndication or reject), not silently drop
		},
		{
			name:     "both IDs swapped (AMF=RAN, RAN=AMF)",
			body:     `{"message_type":"authentication_response","amf_ue_ngap_id_override":1,"ran_ue_ngap_id_override":1}`,
			wantHTTP: 200,
		},
		{
			name:     "very large AMF UE NGAP ID",
			body:     `{"message_type":"authentication_response","amf_ue_ngap_id_override":1099511627775}`,
			wantHTTP: 200,
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
		})
	}
}
