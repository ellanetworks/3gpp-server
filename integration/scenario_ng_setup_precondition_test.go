//go:build integration

// NG Setup precondition (TS 38.413 §8.7.1.1): "This procedure shall be the
// first NGAP procedure triggered after the TNL association has become
// operational." Until NG Setup completes, the association has no NG-C interface
// instance, so the AMF must not serve NGAP procedures on it — regardless of
// message type.

package integration_test

import (
	"fmt"
	"testing"
)

// createGnBWithoutNGSetup opens an SCTP association to the AMF but does not send
// an NG Setup Request, modelling an NG-RAN node that has not completed NG Setup.
func createGnBWithoutNGSetup(t *testing.T, gnbID, name string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"amf_address": "10.3.0.2:38412", "gnb_n2_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "000001",
		"gnb_id": "%s", "name": "%s", "sst": 1, "skip_ng_setup": true
	}`, gnbID, name)

	status, resp := doRequest(t, "POST", "/gnb", body)
	if status != 201 {
		t.Fatalf("create gnb %s (skip_ng_setup): HTTP %d: %s", gnbID, status, resp)
	}

	if got := jsonGet(resp, "ng_setup_response.message_type"); got != "" {
		t.Fatalf("create gnb %s (skip_ng_setup): expected no NG Setup exchange, got ng_setup_response %q", gnbID, got)
	}

	id := jsonGet(resp, "gnb_id")
	if id == "" {
		t.Fatalf("create gnb %s: no gnb_id in response: %s", gnbID, resp)
	}

	t.Cleanup(func() { doRequest(t, "DELETE", "/gnb/"+id, "") })

	return id
}

// assertNotServedBeforeNGSetup sends one NGAP message on a fresh association
// that never completed NG Setup and fails if the AMF served the procedure. The
// handler only ever surfaces the procedure's own response or an Error
// Indication, so a served procedure shows up as a 200 whose message type is not
// ErrorIndication; a drop is a 504 and a refused/closed association a 502 — both
// of which conform to TS 38.413 §8.7.1.1.
func assertNotServedBeforeNGSetup(t *testing.T, context string, status int, body []byte) {
	t.Helper()

	switch status {
	case 200:
		if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
			t.Errorf("%s: AMF served the procedure (%s) on an association that never completed NG Setup; "+
				"NG Setup shall be the first NGAP procedure (TS 38.413 §8.7.1.1)\n  body: %s", context, got, body)
		}
	case 502, 504:
		// 504: AMF returned nothing (dropped). 502: AMF closed/refused the
		// association. Both leave the procedure unserved.
	default:
		t.Fatalf("%s: unexpected HTTP %d\n  body: %s", context, status, body)
	}
}

// TestNGAPMessagesBeforeNGSetupRejected fires a UE-associated initiating message
// (Initial UE Message), a gNB-level UE-associated message (Path Switch Request),
// and an interface-management message (NG Reset) on associations that never
// completed NG Setup, and asserts the AMF serves none of them (TS 38.413
// §8.7.1.1).
func TestNGAPMessagesBeforeNGSetupRejected(t *testing.T) {
	t.Run("InitialUEMessage", func(t *testing.T) {
		gnb := createGnBWithoutNGSetup(t, "0000d0", "no-ngsetup-iue")
		ueID := mustCreateUEWithSUPI(t, gnb, "imsi-001010000000004")

		status, body := doRequest(t, "POST", "/gnb/"+gnb+"/ue/"+ueID+"/ngap",
			`{"message_type":"registration_request"}`)
		assertNotServedBeforeNGSetup(t, "registration (Initial UE Message) before NG Setup", status, body)
	})

	t.Run("PathSwitchRequest", func(t *testing.T) {
		gnb := createGnBWithoutNGSetup(t, "0000d1", "no-ngsetup-psr")

		status, body := doRequest(t, "POST", "/gnb/"+gnb+"/ngap", `{
			"message_type": "path_switch_request",
			"amf_ue_ngap_id": 1,
			"ran_ue_ngap_id": 200,
			"pdu_sessions": [{"id": 1, "dl_teid": 2, "dl_ip": "10.3.0.3"}],
			"wait_for": ["PathSwitchRequestAcknowledge", "PathSwitchRequestFailure", "ErrorIndication"],
			"timeout_ms": 5000
		}`)
		assertNotServedBeforeNGSetup(t, "Path Switch Request before NG Setup", status, body)
	})

	t.Run("NGReset", func(t *testing.T) {
		gnb := createGnBWithoutNGSetup(t, "0000d2", "no-ngsetup-reset")

		status, body := doRequest(t, "POST", "/gnb/"+gnb+"/ngap", `{"message_type":"ng_reset"}`)
		assertNotServedBeforeNGSetup(t, "NG Reset before NG Setup", status, body)
	})
}
