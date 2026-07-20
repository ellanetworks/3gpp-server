// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test5GPDUSessionEstablishment_NGAPIDFuzz(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unknown AMF UE NGAP ID", `{"message_type":"pdu_session_establishment_request","amf_ue_ngap_id_override":99999}`},
		{"inconsistent RAN UE NGAP ID", `{"message_type":"pdu_session_establishment_request","ran_ue_ngap_id_override":99999}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gnbID := mustCreateGNB(t)
			ueID := mustCreateUE(t, gnbID)
			doRegistrationFlow(t, gnbID, ueID)

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tc.body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			assertSpecCompliantErrorIndication(t, body)
		})
	}
}

// PDU session identity 16 falls outside the valid 1-15 range (TS 24.501 §7.3.2 c).
func Test5GPDUSessionEstablishment_ReservedPDUSessionID(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request","pdu_session_id":16}`)

	if status == 504 {
		t.Fatalf("got no response (HTTP 504); TS 24.501 §7.3.2 c) requires a Downlink NAS Transport with 5GMM cause #90\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapDownlinkNASTransport {
		t.Fatalf("ngap.message_type = %q, want DownlinkNASTransport\n  body: %s", got, body)
	}

	assertNASCause(t, body, "nas.5gmm_cause", cause5GMMPayloadWasNotForwarded)
}

func Test5GPDUSessionEstablishment_DuplicateReestablishes(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := establishRegisteredUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapPDUSessionResourceSetupRequest {
		t.Errorf("duplicate establishment ngap.message_type = %q, want PDUSessionResourceSetupRequest (TS 24.501 §5.4.5.2.5 item 12)\n  body: %s", got, body)
	}
}

// raw_nas_pdu goes on the wire unwrapped by any payload container, so these cases
// reach the AMF's outer NAS decoder, never the SMF's 5GSM one.
func Test5GPDUSessionEstablishment_Fuzz(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		wantHTTP         int
		wantNGAPMsgType  string
		wantNASMsgType   string
		wantNASCause5GMM int
		wantInnerNASType string
	}{
		{
			name:             "valid PDU session establishment",
			body:             `{"message_type":"pdu_session_establishment_request"}`,
			wantHTTP:         200,
			wantNGAPMsgType:  ngapPDUSessionResourceSetupRequest,
			wantInnerNASType: nasPDUSessionEstablishmentAccept,
		},
		{
			name:            "raw NAS: empty PDU",
			body:            `{"message_type":"pdu_session_establishment_request","raw_nas_pdu":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: ngapErrorIndication,
		},
		{
			name:             "raw NAS: garbage bytes",
			body:             `{"message_type":"pdu_session_establishment_request","raw_nas_pdu":"deadbeefcafebabe"}`,
			wantHTTP:         200,
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantNASMsgType:   nasStatus5GMM,
			wantNASCause5GMM: cause5GMMProtocolErrorUnspecified,
		},
		{
			name:             "raw NAS: valid 5GMM header but wrong message type",
			body:             `{"message_type":"pdu_session_establishment_request","raw_nas_pdu":"7e00ff"}`,
			wantHTTP:         200,
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantNASMsgType:   nasStatus5GMM,
			wantNASCause5GMM: cause5GMMProtocolErrorUnspecified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGNB(t)
			ueID := mustCreateUE(t, gnbID)

			doRegistrationFlow(t, gnbID, ueID)

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

			if tt.wantNASMsgType != "" {
				if got := jsonGet(body, "nas.message_type"); got != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q\n  body: %s", got, tt.wantNASMsgType, body)
				}
			}

			assertNASCause(t, body, "nas.5gmm_cause", tt.wantNASCause5GMM)

			if tt.wantInnerNASType != "" {
				if got := jsonGet(body, "nas.inner_nas_message_type"); got != tt.wantInnerNASType {
					t.Errorf("nas.inner_nas_message_type = %q, want %q\n  body: %s", got, tt.wantInnerNASType, body)
				}
			}
		})
	}
}

// inner_sm_payload keeps the outer UL NAS Transport well-formed and security-wrapped,
// so the payload reaches the SMF's 5GSM decoder (TS 24.501 §5.4.5.3).
func Test5GPDUSessionEstablishment_InnerSMFuzz(t *testing.T) {
	tests := []struct {
		name             string
		innerSMPayload   string
		wantNGAPMsgType  string
		wantInnerNASType string
		wantNASCause5GSM int
	}{
		{
			name:             "inner SM: garbage bytes (decode fails)",
			innerSMPayload:   "deadbeefcafebabe",
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantInnerNASType: nasPDUSessionEstablishmentReject,
			wantNASCause5GSM: cause5GSMProtocolErrorUnspecified,
		},
		{
			name: "inner SM: valid 5GSM header but wrong message type 0xff",
			// 2E EPD, 01 PDU session ID, 01 PTI, FF unknown msg type
			innerSMPayload:   "2e0101ff",
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantInnerNASType: nasPDUSessionEstablishmentReject,
			wantNASCause5GSM: cause5GSMProtocolErrorUnspecified,
		},
		{
			name: "inner SM: PDU SESSION ESTABLISHMENT ACCEPT (wrong direction, truncated)",
			// 2E EPD, 01 PDU session ID, 01 PTI, C2 msg type = est accept, whose
			// mandatory IEs are absent: decoding fails before the message-type check.
			innerSMPayload:   "2e0101c2",
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantInnerNASType: nasPDUSessionEstablishmentReject,
			wantNASCause5GSM: cause5GSMProtocolErrorUnspecified,
		},
		{
			name: "inner SM: PDU SESSION RELEASE REQUEST (wrong message type)",
			// 2E EPD, 01 PDU session ID, 01 PTI, D1 msg type = release request
			innerSMPayload:   "2e0101d1",
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantInnerNASType: nasPDUSessionEstablishmentReject,
			wantNASCause5GSM: cause5GSMMessageTypeNotCompatibleWithProtocolState,
		},
		{
			name: "inner SM: truncated PDU SESSION ESTABLISHMENT REQUEST (missing mandatory IPMDR)",
			// 2E EPD, 01 PDU session ID, 01 PTI, C1 msg type — missing 2-byte
			// Integrity Protection Maximum Data Rate (mandatory per TS 24.501 §8.3.1).
			innerSMPayload:   "2e0101c1",
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantInnerNASType: nasPDUSessionEstablishmentReject,
			wantNASCause5GSM: cause5GSMProtocolErrorUnspecified,
		},
		{
			name: "inner SM: missing PTI octet",
			// 2E EPD, 01 PDU session ID — missing PTI + msg type + IPMDR.
			innerSMPayload:   "2e01",
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantInnerNASType: nasPDUSessionEstablishmentReject,
			wantNASCause5GSM: cause5GSMProtocolErrorUnspecified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGNB(t)
			ueID := mustCreateUE(t, gnbID)

			doRegistrationFlow(t, gnbID, ueID)

			body := `{"message_type":"pdu_session_establishment_request","inner_sm_payload":"` + tt.innerSMPayload + `"}`

			status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
			}

			if got := jsonGet(resp, "ngap.message_type"); got != tt.wantNGAPMsgType {
				t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, tt.wantNGAPMsgType, resp)
			}

			if got := jsonGet(resp, "nas.inner_nas_message_type"); got != tt.wantInnerNASType {
				t.Errorf("nas.inner_nas_message_type = %q, want %q\n  body: %s", got, tt.wantInnerNASType, resp)
			}

			assertNASCause(t, resp, "nas.5gsm_cause", tt.wantNASCause5GSM)
		})
	}
}

func Test5GPDUSessionEstablishment_InnerSMRequestIEFuzz(t *testing.T) {
	tests := []struct {
		name             string
		innerSMPayload   string
		wantNGAPMsgType  string
		wantInnerNASType string
		wantNASCause5GSM int
	}{
		{
			name: "minimal valid REQUEST (PDU id 1, PTI 1, IPMDR=full speed)",
			// 2E EPD, 01 PDU id, 01 PTI, C1 msg type, FF FF IPMDR
			innerSMPayload:   "2e0101c1ffff",
			wantNGAPMsgType:  ngapPDUSessionResourceSetupRequest,
			wantInnerNASType: nasPDUSessionEstablishmentAccept,
		},
		{
			name: "REQUEST with PDU session type IE = IPv4 (9- IEI = 0x91)",
			// trailer: 91 = IEI 9 + value 1 (IPv4)
			innerSMPayload:   "2e0201c1ffff91",
			wantNGAPMsgType:  ngapPDUSessionResourceSetupRequest,
			wantInnerNASType: nasPDUSessionEstablishmentAccept,
		},
		{
			name:             "REQUEST with SSC mode IE = 1 (A- IEI = 0xA1)",
			innerSMPayload:   "2e0301c1ffffa1",
			wantNGAPMsgType:  ngapPDUSessionResourceSetupRequest,
			wantInnerNASType: nasPDUSessionEstablishmentAccept,
		},
		{
			// TS 24.501 §6.4.1.4.1: an Unstructured session type unsupported for the
			// DNN draws 5GSM cause #28.
			name: "REQUEST with PDU session type = Unstructured (4)",
			// 9- IEI (0x90) with value 4 (Unstructured) = 0x94
			innerSMPayload:   "2e0401c1ffff94",
			wantNGAPMsgType:  ngapDownlinkNASTransport,
			wantInnerNASType: nasPDUSessionEstablishmentReject,
			wantNASCause5GSM: cause5GSMUnknownPDUSessionType,
		},
		{
			name:             "REQUEST with PTI = 1 (smallest valid)",
			innerSMPayload:   "2e0501c1ffff",
			wantNGAPMsgType:  ngapPDUSessionResourceSetupRequest,
			wantInnerNASType: nasPDUSessionEstablishmentAccept,
		},
		{
			name: "REQUEST with PTI = 254 (largest valid)",
			// TS 24.007 §11.2.3.1.1: PTI values 1-254 valid, 0/255 reserved.
			innerSMPayload:   "2e06fec1ffff",
			wantNGAPMsgType:  ngapPDUSessionResourceSetupRequest,
			wantInnerNASType: nasPDUSessionEstablishmentAccept,
		},
		{
			name:             "REQUEST with IPMDR = 0x0000 (lowest)",
			innerSMPayload:   "2e0701c10000",
			wantNGAPMsgType:  ngapPDUSessionResourceSetupRequest,
			wantInnerNASType: nasPDUSessionEstablishmentAccept,
		},
		{
			name:             "REQUEST with always-on PDU session requested (B-, IEI=B1)",
			innerSMPayload:   "2e0801c1ffffb1",
			wantNGAPMsgType:  ngapPDUSessionResourceSetupRequest,
			wantInnerNASType: nasPDUSessionEstablishmentAccept,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID := mustCreateGNB(t)
			ueID := mustCreateUE(t, gnbID)

			doRegistrationFlow(t, gnbID, ueID)

			body := `{"message_type":"pdu_session_establishment_request","inner_sm_payload":"` + tt.innerSMPayload + `"}`

			status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
			}

			if got := jsonGet(resp, "ngap.message_type"); got != tt.wantNGAPMsgType {
				t.Errorf("ngap.message_type = %q, want %q\n  body: %s", got, tt.wantNGAPMsgType, resp)
			}

			if got := jsonGet(resp, "nas.inner_nas_message_type"); got != tt.wantInnerNASType {
				t.Errorf("nas.inner_nas_message_type = %q, want %q\n  body: %s", got, tt.wantInnerNASType, resp)
			}

			assertNASCause(t, resp, "nas.5gsm_cause", tt.wantNASCause5GSM)
		})
	}
}
