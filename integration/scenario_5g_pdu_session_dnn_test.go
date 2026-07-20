// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test5GPDUSessionEstablishment_UnknownDNN(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := mustCreateUEWithDNN(t, gnbID, "unconfigured")
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status == 504 {
		t.Fatalf("no response to an unknown-DNN establishment; TS 24.501 §9.11.4.2 requires an Establishment Reject with 5GSM cause #70\n  body: %s", body)
	}

	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapDownlinkNASTransport {
		t.Fatalf("ngap.message_type = %q, want DownlinkNASTransport\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentReject {
		t.Errorf("nas.inner_nas_message_type = %q, want pdu_session_establishment_reject\n  body: %s", got, body)
	}

	assertNASCause(t, body, "nas.5gsm_cause", cause5GSMMissingOrUnknownDNNInASlice)
}

func mustCreateUEWithDNN(t *testing.T, gnbID, dnn string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"supi": "imsi-001010000000001",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": %q,
		"routing_indicator": "0",
		"protection_scheme": "0",
		"public_key_id": "0",
		"imeisv": "1122334455667788"
	}`, dnn)

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
