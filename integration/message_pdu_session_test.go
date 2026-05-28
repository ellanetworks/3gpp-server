//go:build integration

package integration_test

import (
	"testing"
)

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
		wantNASCause5GMM string
		wantInnerNASType string
	}{
		{
			name:             "valid PDU session establishment",
			body:             `{"message_type":"pdu_session_establishment_request"}`,
			wantHTTP:         200,
			wantNGAPMsgType:  "PDUSessionResourceSetupRequest",
			wantInnerNASType: "pdu_session_establishment_accept",
		},
		{
			name:            "raw NAS: empty PDU",
			body:            `{"message_type":"pdu_session_establishment_request","raw_nas_pdu":""}`,
			wantHTTP:        200,
			wantNGAPMsgType: "ErrorIndication",
		},
		{
			name:             "raw NAS: garbage bytes",
			body:             `{"message_type":"pdu_session_establishment_request","raw_nas_pdu":"deadbeefcafebabe"}`,
			wantHTTP:         200,
			wantNGAPMsgType:  "DownlinkNASTransport",
			wantNASMsgType:   "status_5gmm",
			wantNASCause5GMM: "111",
		},
		{
			name:             "raw NAS: valid 5GMM header but wrong message type",
			body:             `{"message_type":"pdu_session_establishment_request","raw_nas_pdu":"7e00ff"}`,
			wantHTTP:         200,
			wantNGAPMsgType:  "DownlinkNASTransport",
			wantNASMsgType:   "status_5gmm",
			wantNASCause5GMM: "111",
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

			if tt.wantNASCause5GMM != "" {
				if got := jsonGet(body, "nas.cause_5gmm"); got != tt.wantNASCause5GMM {
					t.Errorf("nas.cause_5gmm = %q, want %q\n  body: %s", got, tt.wantNASCause5GMM, body)
				}
			}

			if tt.wantInnerNASType != "" {
				if got := jsonGet(body, "nas.inner_nas_message_type"); got != tt.wantInnerNASType {
					t.Errorf("nas.inner_nas_message_type = %q, want %q\n  body: %s", got, tt.wantInnerNASType, body)
				}
			}
		})
	}
}
