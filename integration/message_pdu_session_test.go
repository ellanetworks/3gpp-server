// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// TestPDUSessionEstablishment_NGAPIDFuzz sends a PDU Session Establishment
// Request on an established connection with a wrong UE NGAP ID and expects a
// spec-compliant Error Indication (TS 38.413 §10.6, §8.7.5.2).
func TestPDUSessionEstablishment_NGAPIDFuzz(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unknown AMF UE NGAP ID", `{"message_type":"pdu_session_establishment_request","amf_ue_ngap_id_override":99999}`},
		{"inconsistent RAN UE NGAP ID", `{"message_type":"pdu_session_establishment_request","ran_ue_ngap_id_override":99999}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gnbID := mustCreateGnB(t)
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

// TestPDUSessionEstablishment_ReservedPDUSessionID sends an establishment request
// with a reserved PDU session identity value (16 is outside the 1-15 range). Per
// TS 24.501 §7.3.2 c) the AMF returns the message in a Downlink NAS Transport
// with 5GMM cause #90 "payload was not forwarded".
func TestPDUSessionEstablishment_ReservedPDUSessionID(t *testing.T) {
	gnbID := mustCreateGnB(t)
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

	assertNASCause(t, body, "nas.cause_5gmm", cause5GMMPayloadWasNotForwarded)
}

// TestPDUSessionEstablishment_DuplicateReestablishes sends a second
// establishment request for an already-active PDU session. Per TS 24.501
// §5.4.5.2.5 item 12 the AMF locally releases it and re-establishes, so the gNB
// receives a fresh PDU Session Resource Setup Request.
func TestPDUSessionEstablishment_DuplicateReestablishes(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := establishRegisteredUE(t, gnbID) // registered UE with an active PDU session

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapPDUSessionResourceSetupRequest {
		t.Errorf("duplicate establishment ngap.message_type = %q, want PDUSessionResourceSetupRequest (TS 24.501 §5.4.5.2.5 item 12)\n  body: %s", got, body)
	}
}

// TestPDUSessionEstablishment_Fuzz drives the PDU session establishment endpoint
// with both well-formed and malformed top-level NAS payloads. When raw_nas_pdu
// is supplied, the 3gpp-server sends those bytes as the NAS PDU IE of an
// UplinkNASTransport (rather than wrapping them in a UL NAS TRANSPORT payload
// container), so these cases exercise the AMF's outer NAS decoder, not the
// SMF's GSM decoder.
//
// Expected AMF behaviour per TS 24.501 §4.4.4.3 and TS 38.413:
//   - NGAP NAS-PDU IE empty       → ASN.1 reject → ErrorIndication
//   - NAS payload undecodable     → 5GMM STATUS, cause #111 Protocol error, unspecified
//   - Plain msg type not allowed  → 5GMM STATUS, cause #111
func TestPDUSessionEstablishment_Fuzz(t *testing.T) {
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
			gnbID := mustCreateGnB(t)
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

			assertNASCause(t, body, "nas.cause_5gmm", tt.wantNASCause5GMM)

			if tt.wantInnerNASType != "" {
				if got := jsonGet(body, "nas.inner_nas_message_type"); got != tt.wantInnerNASType {
					t.Errorf("nas.inner_nas_message_type = %q, want %q\n  body: %s", got, tt.wantInnerNASType, body)
				}
			}
		})
	}
}

// TestPDUSessionEstablishment_InnerSMFuzz drives the AMF→SMF SM-payload path
// with a malformed *inner* SM payload while keeping the outer UL NAS Transport
// correctly built and security-wrapped. Unlike raw_nas_pdu (which bypasses
// security and is rejected at the AMF 5GMM layer), inner_sm_payload exercises
// the SMF's GsmMessageDecode + reject build path and the AMF's fallback per
// TS 24.501 §5.4.5.3.
//
// Expected behaviour:
//   - Inner SM payload undecodable as 5GSM
//     → SMF builds PDU SESSION ESTABLISHMENT REJECT with 5GSM cause #111
//     → AMF forwards inside DL NAS TRANSPORT
//   - Inner SM payload decodes but message type is not "establishment request"
//     → SMF builds reject with 5GSM cause #98
//     → AMF forwards inside DL NAS TRANSPORT
//   - Inner SM payload absent entirely (empty bytes)
//     → SMF can't decode → reject with cause #111 (as above)
func TestPDUSessionEstablishment_InnerSMFuzz(t *testing.T) {
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
			// 2E EPD, 01 PDU session ID, 01 PTI, C2 msg type = est accept.
			// ACCEPT has mandatory IEs (Session AMBR, Authorized QoS rules, etc.)
			// so the 4-byte input fails GsmMessageDecode before the message-type
			// check fires. SMF therefore returns #111 (protocol error, unspecified).
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
			gnbID := mustCreateGnB(t)
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

			assertNASCause(t, resp, "nas.cause_5gsm", tt.wantNASCause5GSM)
		})
	}
}

// TestPDUSessionEstablishment_InnerSMRequestIEFuzz drives a well-formed
// PDU SESSION ESTABLISHMENT REQUEST through the AMF→SMF path with various
// edge-case IE values per TS 24.501 §8.3.1 / §9.6. These exercise the SMF
// decoder and SM context allocation under unusual input.
func TestPDUSessionEstablishment_InnerSMRequestIEFuzz(t *testing.T) {
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
			// TS 24.501 §6.4.1.4.1: when the requested PDU session type is
			// "Unstructured" or "Ethernet" and the network does not support
			// it for the DNN, the SMF shall reject with 5GSM cause #28
			// "unknown PDU session type".
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
			gnbID := mustCreateGnB(t)
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

			assertNASCause(t, resp, "nas.cause_5gsm", tt.wantNASCause5GSM)
		})
	}
}
