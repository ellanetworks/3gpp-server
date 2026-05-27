//go:build integration

// Tests for InitialUEMessage (TS 38.413 §9.2.5.1) and the NAS RegistrationRequest
// (TS 24.501 §8.2.6) it carries. Each row crafts a specific IE combination and verifies
// the AMF response.

package integration_test

import (
	"testing"
)

func TestInitialUEMessage(t *testing.T) {
	gnbID := mustCreateGnB(t)

	tests := []struct {
		name     string
		body     string
		wantHTTP int
		// NGAP-level checks on the response
		wantNGAPMessageType string
		// NAS-level checks on the decoded NAS PDU inside the response
		wantNASMessageType string
		wantNASFields      map[string]fieldCheck
	}{
		// --- Valid registration requests ---
		{
			name:                "default initial registration",
			body:                `{"message_type":"registration_request"}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
			wantNASFields: map[string]fieldCheck{
				"rand": nonEmpty,
				"autn": nonEmpty,
				"abba": nonEmpty,
			},
		},
		{
			name:                "explicit registration_type=1 (initial)",
			body:                `{"message_type":"registration_request","registration_type":1}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
			wantNASFields: map[string]fieldCheck{
				"rand": nonEmpty,
				"autn": nonEmpty,
			},
		},
		// --- NAS IE variations (TS 24.501 §8.2.6 optional IEs) ---
		{
			name: "with requested_nssai SST=1",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1}]
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
			wantNASFields: map[string]fieldCheck{
				"rand": nonEmpty,
				"autn": nonEmpty,
			},
		},
		{
			name: "with requested_nssai SST=1 SD=000001",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1,"sd":"000001"}]
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with 5GMM capability",
			body: `{
				"message_type":"registration_request",
				"capability_5gmm":"07"
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with overridden UE security capability (NIA1+NIA2, NEA1+NEA2)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"6060"
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with follow_on_request=0",
			body: `{
				"message_type":"registration_request",
				"follow_on_request":0
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with DRX parameters",
			body: `{
				"message_type":"registration_request",
				"requested_drx_parameters":2
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with MICO indication",
			body: `{
				"message_type":"registration_request",
				"mico_indication":1
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with UE status (both N1 and S1 registered)",
			body: `{
				"message_type":"registration_request",
				"ue_status":3
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with network slicing indication (DCNI+NSSCI)",
			body: `{
				"message_type":"registration_request",
				"network_slicing_indication":3
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with multiple optional IEs combined",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1}],
				"capability_5gmm":"07",
				"requested_drx_parameters":2,
				"follow_on_request":1
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		// --- Bizarre / fuzz-style NAS IEs ---
		{
			name: "security capability with only null algorithms (EA0+IA0)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"8080"
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
		},
		{
			name: "security capability with no algorithms at all",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"0000"
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
		},
		{
			name: "empty requested_nssai array",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[]
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with S1 UE network capability (EPC interworking)",
			body: `{
				"message_type":"registration_request",
				"s1_ue_network_capability":"e0e0"
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		{
			name: "with EPS bearer context status",
			body: `{
				"message_type":"registration_request",
				"eps_bearer_context_status":"0000"
			}`,
			wantHTTP:            200,
			wantNGAPMessageType: "DownlinkNASTransport",
			wantNASMessageType:  "authentication_request",
		},
		// --- Error cases ---
		{
			name:     "unsupported message type",
			body:     `{"message_type":"authentication_response"}`,
			wantHTTP: 400,
		},
		{
			name:     "empty message type",
			body:     `{"message_type":""}`,
			wantHTTP: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ueID := mustCreateUE(t, gnbID)

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tt.body)
			if status != tt.wantHTTP {
				t.Fatalf("HTTP %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}

			if tt.wantHTTP != 200 {
				return
			}

			if tt.wantNGAPMessageType != "" {
				if got := jsonGet(body, "ngap.message_type"); got != tt.wantNGAPMessageType {
					t.Errorf("ngap.message_type = %q, want %q", got, tt.wantNGAPMessageType)
				}
			}

			if tt.wantNASMessageType != "" {
				if got := jsonGet(body, "nas.message_type"); got != tt.wantNASMessageType {
					t.Errorf("nas.message_type = %q, want %q", got, tt.wantNASMessageType)
				}
			}

			for field, check := range tt.wantNASFields {
				got := jsonGet(body, "nas."+field)
				check.assert(t, field, got)
			}
		})
	}
}
