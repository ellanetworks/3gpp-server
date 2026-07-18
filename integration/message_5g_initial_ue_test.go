// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"strconv"
	"testing"
)

func Test5GInitialUEMessage_Valid(t *testing.T) {
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
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
			wantNASFields: map[string]fieldCheck{
				"rand": nonEmpty,
				"autn": nonEmpty,
				"abba": nonEmpty,
			},
		},
		{
			name:            "explicit registration_type=1 (initial)",
			body:            fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d}`, registrationTypeInitial),
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "with requested_nssai matching AMF slice",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "with requested_nssai SST=1 SD=000001",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1,"sd":"000001"}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "with 5GMM capability",
			body: `{
				"message_type":"registration_request",
				"capability_5gmm":"07"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "with overridden UE security capability (NIA1+NIA2, NEA1+NEA2)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"6060"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "with follow_on_request=0",
			body: `{
				"message_type":"registration_request",
				"follow_on_request":0
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "with DRX parameters",
			body: `{
				"message_type":"registration_request",
				"requested_drx_parameters":2
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
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
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ueID := mustCreateUE(t, gnbID)
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

func Test5GInitialUEMessage_Fuzz(t *testing.T) {
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
			name:            "unknown subscriber SUPI (not provisioned in AMF)",
			body:            `{"message_type":"registration_request","mobile_identity_override":"0100f110f00000000001"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasRegistrationReject,
		},
		{
			name:            "registration_type=2 (mobility updating) for fresh UE",
			body:            fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d}`, registrationTypeMobility),
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name:            "registration_type=3 (periodic) for fresh UE",
			body:            fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d}`, registrationTypePeriodic),
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name:            "registration_type=4 (emergency) for fresh UE",
			body:            fmt.Sprintf(`{"message_type":"registration_request","registration_type":%d}`, registrationTypeEmergency),
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name:            "mobile identity override: single zero byte",
			body:            `{"message_type":"registration_request","mobile_identity_override":"00"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name:            "mobile identity override: empty string",
			body:            `{"message_type":"registration_request","mobile_identity_override":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasStatus5GMM,
		},
		{
			name:            "mobile identity override: type byte only (no content)",
			body:            `{"message_type":"registration_request","mobile_identity_override":"01"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name:            "mobile identity override: 255 bytes of 0xff",
			body:            `{"message_type":"registration_request","mobile_identity_override":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name: "security capability: only null algorithms (EA0+IA0)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"8080"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name: "security capability: no algorithms at all (0x0000)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"0000"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name: "security capability: all algorithms enabled (0xffff)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "security capability: truncated to 1 byte",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"e0"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name: "security capability: extended to 4 bytes (with EPS algorithms)",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"e0e0e0e0"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "security capability: maximum length 8 bytes",
			body: `{
				"message_type":"registration_request",
				"ue_security_capability":"e0e0e0e0e0e0e0e0"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "requested NSSAI with SST the AMF does not serve",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":99}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "requested NSSAI with many slices (4 including unknown)",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":1},{"sst":2},{"sst":3},{"sst":255}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "requested NSSAI with SST=0",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":0}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "requested NSSAI with SST=255 SD=ffffff",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[{"sst":255,"sd":"ffffff"}]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "empty requested NSSAI array",
			body: `{
				"message_type":"registration_request",
				"requested_nssai":[]
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "ng_ksi=0 (implies existing security context)",
			body: `{
				"message_type":"registration_request",
				"ng_ksi":0
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name: "ng_ksi=6",
			body: `{
				"message_type":"registration_request",
				"ng_ksi":6
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name: "PDU session status set when no sessions exist",
			body: `{
				"message_type":"registration_request",
				"pdu_session_status":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "uplink data status set when no sessions exist",
			body: `{
				"message_type":"registration_request",
				"uplink_data_status":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
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
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "EPS bearer context status with all bearers active",
			body: `{
				"message_type":"registration_request",
				"eps_bearer_context_status":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "allowed PDU session status claiming all sessions allowed",
			body: `{
				"message_type":"registration_request",
				"allowed_pdu_session_status":"ffff"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "NAS message container with garbage payload",
			body: `{
				"message_type":"registration_request",
				"nas_message_container":"deadbeefcafebabe"
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
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
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "RRC establishment cause: high-priority-access",
			body: fmt.Sprintf(`{
				"message_type":"registration_request",
				"rrc_establishment_cause":%d
			}`, rrcEstablishmentCauseHighPriorityAccess),
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "RRC establishment cause: mo-voice-call",
			body: fmt.Sprintf(`{
				"message_type":"registration_request",
				"rrc_establishment_cause":%d
			}`, rrcEstablishmentCauseMoVoiceCall),
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "RRC establishment cause: out-of-range value",
			body: fmt.Sprintf(`{
				"message_type":"registration_request",
				"rrc_establishment_cause":%d
			}`, rrcEstablishmentCauseOutOfRange),
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name: "UE context request omitted",
			body: `{
				"message_type":"registration_request",
				"ue_context_request":-1
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasAuthenticationRequest,
		},
		{
			name: "RAN UE NGAP ID override: zero",
			body: `{
				"message_type":"registration_request",
				"ran_ue_ngap_id_override":0
			}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name:            "raw NAS: completely empty PDU → ErrorIndication",
			body:            `{"message_type":"registration_request","raw_nas_pdu":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name: "raw NAS: single byte 0x7e (5GMM EPD only)",
			// TS 24.501 §7.2.1: too short for a message type IE, so it is ignored — no reply.
			body:     `{"message_type":"registration_request","raw_nas_pdu":"7e"}`,
			wantHTTP: 504,
		},
		{
			name: "raw NAS: two bytes (EPD + security header, no message type)",
			// TS 24.501 §7.2.1: too short for a message type IE, so it is ignored — no reply.
			body:     `{"message_type":"registration_request","raw_nas_pdu":"7e00"}`,
			wantHTTP: 504,
		},
		{
			name:            "raw NAS: wrong EPD (not 5GMM)",
			body:            `{"message_type":"registration_request","raw_nas_pdu":"2e004100"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			// TS 24.501 §7.4: reception of a 5GMM message is foreseen in this state, so
			// the AMF should answer an undefined message type with 5GMM STATUS and #97.
			name:            "raw NAS: valid 5GMM header but unknown message type 0xff",
			body:            `{"message_type":"registration_request","raw_nas_pdu":"7e00ff"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
			wantNASMsgType:  nasStatus5GMM,
			wantNASFields: map[string]fieldCheck{
				"5gmm_cause": {wantExact: strconv.Itoa(cause5GMMMessageTypeNonExistent)},
			},
		},
		{
			name:            "raw NAS: RegistrationRequest truncated after mandatory header",
			body:            `{"message_type":"registration_request","raw_nas_pdu":"7e004179"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
		},
		{
			name:            "raw NAS: integrity-protected wrapper around garbage",
			body:            `{"message_type":"registration_request","raw_nas_pdu":"7e01deadbeef00cafebabe"}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapDownlinkNASTransport,
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

			if tt.wantNGAPMsgType != "" {
				if got := jsonGet(body, "ngap.message_type"); got != tt.wantNGAPMsgType {
					t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, tt.wantNGAPMsgType, body)
				}
			}

			ngapMsgType := jsonGet(body, "ngap.message_type")
			nasMsgType := jsonGet(body, "nas.message_type")

			if tt.wantNASMsgType != "" {
				if nasMsgType != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q\n  body: %s", nasMsgType, tt.wantNASMsgType, body)
				}
			} else if nasMsgType == "" && ngapMsgType != ngapErrorIndication {
				t.Errorf("nas.message_type is empty — AMF response did not contain a decodable NAS PDU\n  body: %s", body)
			}

			for field, check := range tt.wantNASFields {
				check.assert(t, field, jsonGet(body, "nas."+field))
			}
		})
	}
}
