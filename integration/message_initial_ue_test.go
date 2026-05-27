//go:build integration

// Tests for InitialUEMessage (TS 38.413 §9.2.5.1) and the NAS RegistrationRequest
// (TS 24.501 §8.2.6) it carries. Each row crafts a specific IE combination and verifies
// the AMF response.
//
// Tests are grouped:
//   - Valid: correct IEs, verify AMF responds with authentication_request
//   - IE variations: each optional NAS IE individually, confirm AMF tolerance
//   - Fuzz: malformed, oversized, truncated, conflicting, or spec-violating IEs
//     that probe AMF robustness

package integration_test

import (
	"testing"
)

func TestInitialUEMessage_Valid(t *testing.T) {
	gnbID := mustCreateGnB(t)

	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantNGAPMsgType string
		wantNASMsgType  string
		wantNASFields   map[string]fieldCheck
	}{
		{
			name:            "default initial registration",
			body:            `{"message_type":"registration_request"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
			wantNASFields: map[string]fieldCheck{
				"rand": nonEmpty,
				"autn": nonEmpty,
				"abba": nonEmpty,
			},
		},
		{
			name:            "explicit registration_type=1 (initial)",
			body:            `{"message_type":"registration_request","registration_type":1}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "with requested_nssai matching AMF slice",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "with requested_nssai SST=1 SD=000001",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1,"sd":"000001"}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "with 5GMM capability",
			body: `{
				"message_type":"registration_request",
				"capability_5gmm":"07"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "with overridden UE security capability (NIA1+NIA2, NEA1+NEA2)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"6060"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "with follow_on_request=0",
			body: `{
				"message_type":"registration_request",
				"follow_on_request":0
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "with DRX parameters",
			body: `{
				"message_type":"registration_request",
				"requested_drx_parameters":2
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "with multiple optional IEs combined",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1}],
				"capability_5gmm":"07",
				"requested_drx_parameters":2,
				"follow_on_request":1,
				"s1_ue_network_capability":"e0e0"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ueID := mustCreateUE2(t, gnbID)
			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tt.body)
			if status != tt.wantHTTP {
				t.Fatalf("HTTP %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}
			if tt.wantNGAPMsgType != "" {
				if got := jsonGet(body, "ngap.message_type"); got != tt.wantNGAPMsgType {
					t.Errorf("ngap.message_type = %q, want %q", got, tt.wantNGAPMsgType)
				}
			}
			if tt.wantNASMsgType != "" {
				if got := jsonGet(body, "nas.message_type"); got != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q", got, tt.wantNASMsgType)
				}
			}
			for field, check := range tt.wantNASFields {
				check.assert(t, field, jsonGet(body, "nas."+field))
			}
		})
	}
}

func TestInitialUEMessage_Fuzz(t *testing.T) {
	gnbID := mustCreateGnB(t)

	tests := []struct {
		name string
		body string
		// What we expect from the AMF. For fuzz tests the AMF should either
		// respond with a valid NAS message (reject or auth request) or we
		// get a DownlinkNASTransport. It must NOT crash or hang.
		wantHTTP        int
		wantNGAPMsgType string
		// If set, assert the NAS message type. Empty means "any NAS response is fine".
		wantNASMsgType string
		// If set, assert this NAS field has this value.
		wantNASFields map[string]fieldCheck
	}{
		// --- Unknown / wrong subscriber ---
		{
			name:            "unknown subscriber SUPI (not provisioned in AMF)",
			body:            `{"message_type":"registration_request","mobile_identity_override":"0100f110f00000000001"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "registration_reject",
		},
		// --- Wrong registration types for unknown UE ---
		{
			name: "registration_type=2 (mobility updating) for fresh UE",
			body: `{"message_type":"registration_request","registration_type":2}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "registration_type=3 (periodic) for fresh UE",
			body: `{"message_type":"registration_request","registration_type":3}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "registration_type=4 (emergency) for fresh UE",
			body: `{"message_type":"registration_request","registration_type":4}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		// --- Malformed mobile identity ---
		{
			name:            "mobile identity override: single zero byte",
			body:            `{"message_type":"registration_request","mobile_identity_override":"00"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name:            "mobile identity override: empty string",
			body:            `{"message_type":"registration_request","mobile_identity_override":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "registration_reject",
		},
		{
			name:            "mobile identity override: type byte only (no content)",
			body:            `{"message_type":"registration_request","mobile_identity_override":"01"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name:            "mobile identity override: 255 bytes of 0xff",
			body:            `{"message_type":"registration_request","mobile_identity_override":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		// --- UE security capability edge cases ---
		{
			name: "security capability: only null algorithms (EA0+IA0)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"8080"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "security capability: no algorithms at all (0x0000)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"0000"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "security capability: all algorithms enabled (0xffff)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "security capability: truncated to 1 byte",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"e0"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "security capability: extended to 4 bytes (with EPS algorithms)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"e0e0e0e0"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "security capability: maximum length 8 bytes",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"e0e0e0e0e0e0e0e0"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		// --- NSSAI edge cases ---
		{
			name: "requested NSSAI with SST the AMF does not serve",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":99}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "requested NSSAI with many slices (4 including unknown)",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1},{"sst":2},{"sst":3},{"sst":255}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "requested NSSAI with SST=0",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":0}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "requested NSSAI with SST=255 SD=ffffff",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":255,"sd":"ffffff"}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "empty requested NSSAI array",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		// --- ngKSI edge cases ---
		{
			name: "ng_ksi=0 (implies existing security context)",
			body: `{
				"message_type":"registration_request",
				"ng_ksi":0
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		{
			name: "ng_ksi=6",
			body: `{
				"message_type":"registration_request",
				"ng_ksi":6
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
		},
		// --- Conflicting / nonsensical IE combinations ---
		{
			name: "PDU session status set when no sessions exist",
			body: `{
				"message_type":"registration_request",
				"pdu_session_status":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "uplink data status set when no sessions exist",
			body: `{
				"message_type":"registration_request",
				"uplink_data_status":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "MICO + network slicing + UE status all set",
			body: `{
				"message_type":"registration_request",
				"mico_indication":1,
				"network_slicing_indication":3,
				"ue_status":3
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "EPS bearer context status with all bearers active",
			body: `{
				"message_type":"registration_request",
				"eps_bearer_context_status":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		{
			name: "allowed PDU session status claiming all sessions allowed",
			body: `{
				"message_type":"registration_request",
				"allowed_pdu_session_status":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		// --- NAS message container (nested NAS) ---
		{
			name: "NAS message container with garbage payload",
			body: `{
				"message_type":"registration_request",
				"nas_message_container":"deadbeefcafebabe"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		// --- Kitchen sink: every optional IE at once ---
		{
			name: "all optional IEs set simultaneously",
			body: `{
				"message_type":"registration_request",
				"registration_type":1,
				"ng_ksi":7,
				"follow_on_request":1,
				"capability_5gmm":"07",
				"ue_security_capability":"e0e0",
				"requested_nssai":[{"sst":1}],
				"s1_ue_network_capability":"e0e0",
				"requested_drx_parameters":2,
				"mico_indication":0,
				"ue_status":1,
				"network_slicing_indication":0,
				"pdu_session_status":"0000",
				"uplink_data_status":"0000",
				"eps_bearer_context_status":"0000",
				"allowed_pdu_session_status":"0000",
				"ues_usage_setting":0
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: "DownlinkNASTransport",
			wantNASMsgType:  "authentication_request",
		},
		// --- API-level errors (3gpp-server rejects before sending) ---
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
			ueID := mustCreateUE2(t, gnbID)
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

			nasMsgType := jsonGet(body, "nas.message_type")
			if tt.wantNASMsgType != "" {
				if nasMsgType != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q\n  body: %s", nasMsgType, tt.wantNASMsgType, body)
				}
			} else if nasMsgType == "" {
				t.Errorf("nas.message_type is empty — AMF response did not contain a decodable NAS PDU\n  body: %s", body)
			}

			for field, check := range tt.wantNASFields {
				check.assert(t, field, jsonGet(body, "nas."+field))
			}
		})
	}
}
