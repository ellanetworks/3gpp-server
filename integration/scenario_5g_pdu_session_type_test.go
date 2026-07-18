// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test5GPDUSessionTypeNegotiation(t *testing.T) {
	cases := []struct {
		name        string
		dnn         string
		reqType     int
		accept      bool
		wantSelType int
		wantCause   int // 0 means the cause IE must be absent
	}{
		{
			name:        "IPv4v6 request on IPv4-only DNN accepts IPv4 with #50",
			dnn:         "internet",
			reqType:     pduSessionTypeIPv4IPv6,
			accept:      true,
			wantSelType: pduSessionTypeIPv4,
			wantCause:   cause5GSMPDUSessionTypeIPv4OnlyAllowed,
		},
		{
			name:        "IPv4v6 request on IPv6-only DNN accepts IPv6 with #51",
			dnn:         "internet6",
			reqType:     pduSessionTypeIPv4IPv6,
			accept:      true,
			wantSelType: pduSessionTypeIPv6,
			wantCause:   cause5GSMPDUSessionTypeIPv6OnlyAllowed,
		},
		{
			name:        "IPv4v6 request on dual-stack DNN accepts IPv4v6 with no cause",
			dnn:         "internet46",
			reqType:     pduSessionTypeIPv4IPv6,
			accept:      true,
			wantSelType: pduSessionTypeIPv4IPv6,
			wantCause:   0,
		},
		{
			name:      "IPv6 request on IPv4-only DNN is rejected with #50",
			dnn:       "internet",
			reqType:   pduSessionTypeIPv6,
			accept:    false,
			wantCause: cause5GSMPDUSessionTypeIPv4OnlyAllowed,
		},
		{
			name:      "IPv4 request on IPv6-only DNN is rejected with #51",
			dnn:       "internet6",
			reqType:   pduSessionTypeIPv4,
			accept:    false,
			wantCause: cause5GSMPDUSessionTypeIPv6OnlyAllowed,
		},
		{
			name:      "Ethernet request on IPv4-only DNN is rejected with #28",
			dnn:       "internet",
			reqType:   pduSessionTypeEthernet,
			accept:    false,
			wantCause: cause5GSMUnknownPDUSessionType,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gnbID := mustCreateGnB(t)
			ueID := mustCreateUETypeDNN(t, gnbID, tc.dnn, tc.reqType)
			doRegistrationFlow(t, gnbID, ueID)

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
				`{"message_type":"pdu_session_establishment_request"}`)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			if tc.accept {
				assertTypeAccept(t, body, tc.wantSelType, tc.wantCause)
			} else {
				assertTypeReject(t, body, tc.wantCause)
			}
		})
	}
}

func assertTypeAccept(t *testing.T, body []byte, wantSelType, wantCause int) {
	t.Helper()

	if got := jsonGet(body, "ngap.message_type"); got != ngapPDUSessionResourceSetupRequest {
		t.Fatalf("ngap.message_type = %q, want PDUSessionResourceSetupRequest (accept)\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentAccept {
		t.Fatalf("nas.inner_nas_message_type = %q, want pdu_session_establishment_accept\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.pdu_session_type"); got != fmt.Sprintf("%d", wantSelType) {
		t.Errorf("nas.pdu_session_type = %q, want %d (TS 24.501 §6.4.1.3)\n  body: %s", got, wantSelType, body)
	}

	if wantCause == 0 {
		if got := jsonGet(body, "nas.5gsm_cause"); got != "" {
			t.Errorf("nas.5gsm_cause = %q, want absent (full requested type granted)\n  body: %s", got, body)
		}

		return
	}

	assertNASCause(t, body, "nas.5gsm_cause", wantCause)
}

func assertTypeReject(t *testing.T, body []byte, wantCause int) {
	t.Helper()

	if got := jsonGet(body, "ngap.message_type"); got != ngapDownlinkNASTransport {
		t.Fatalf("ngap.message_type = %q, want DownlinkNASTransport (reject)\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentReject {
		t.Fatalf("nas.inner_nas_message_type = %q, want pdu_session_establishment_reject\n  body: %s", got, body)
	}

	assertNASCause(t, body, "nas.5gsm_cause", wantCause)
}

func mustCreateUETypeDNN(t *testing.T, gnbID, dnn string, pduType int) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"supi": "imsi-001010000000001",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": %q, "pdu_session_type": %d,
		"routing_indicator": "0",
		"protection_scheme": "0",
		"public_key_id": "0",
		"imeisv": "1122334455667788"
	}`, dnn, pduType)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create ue: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	if ueID == "" {
		t.Fatal("create ue: no ue_id in response")
	}

	return ueID
}
