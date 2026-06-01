//go:build integration

// NG Reset (TS 38.413 §8.7.4): the gNB resets the whole NG interface or a
// subset of UE associations; the AMF answers with NG Reset Acknowledge.
// Assertions follow the spec; a failure means Ella Core deviates.

package integration_test

import (
	"encoding/json"
	"strconv"
	"testing"
)

// ngapHasConnection reports whether the response's NGAP IE list contains a
// UE-associated NG-connection item with the given AMF and RAN UE NGAP IDs.
func ngapHasConnection(body []byte, amfID, ranID int64) bool {
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return false
	}

	ngapObj, ok := top["ngap"].(map[string]any)
	if !ok {
		return false
	}

	ies, ok := ngapObj["ies"].([]any)
	if !ok {
		return false
	}

	for _, ie := range ies {
		iem, ok := ie.(map[string]any)
		if !ok {
			continue
		}

		amf, aok := iem["amf_ue_ngap_id"].(float64)
		ran, rok := iem["ran_ue_ngap_id"].(float64)
		if aok && rok && int64(amf) == amfID && int64(ran) == ranID {
			return true
		}
	}

	return false
}

// TestNGReset_All resets the whole NG interface. Per TS 38.413 §8.7.4.2.2 the
// AMF releases the UE associations and answers with NG Reset Acknowledge.
func TestNGReset_All(t *testing.T) {
	gnbID := mustCreateGnB(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap",
		`{"message_type":"ng_reset"}`)
	if status != 200 {
		t.Fatalf("ng_reset: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapNGResetAcknowledge {
		t.Errorf("ngap.message_type = %q, want NGResetAcknowledge (TS 38.413 §8.7.4)\n  body: %s", got, body)
	}
}

// TestNGReset_Partial resets a single registered UE's association. Per TS 38.413
// §8.7.4.2.2 the AMF shall include, for each reset connection, the AMF UE NGAP
// ID and RAN UE NGAP ID in the NG Reset Acknowledge's UE-associated Logical
// NG-connection List.
func TestNGReset_Partial(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	// The gNB lists this UE's NGAP IDs in the NG Reset, so the acknowledge must
	// echo them back.
	_, ueBody := doRequest(t, "GET", "/gnb/"+gnbID+"/ue/"+ueID, "")
	amfID, err := strconv.ParseInt(jsonGet(ueBody, "amf_ue_ngap_id"), 10, 64)
	if err != nil {
		t.Fatalf("parse amf_ue_ngap_id: %v\n  body: %s", err, ueBody)
	}
	ranID, err := strconv.ParseInt(jsonGet(ueBody, "ran_ue_ngap_id"), 10, 64)
	if err != nil {
		t.Fatalf("parse ran_ue_ngap_id: %v\n  body: %s", err, ueBody)
	}

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap",
		`{"message_type":"ng_reset","reset_ue_ids":["`+ueID+`"]}`)
	if status != 200 {
		t.Fatalf("ng_reset: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapNGResetAcknowledge {
		t.Fatalf("ngap.message_type = %q, want NGResetAcknowledge\n  body: %s", got, body)
	}

	if !ngapHasConnection(body, amfID, ranID) {
		t.Errorf("NG Reset Acknowledge did not echo the reset connection (amf=%d ran=%d) (TS 38.413 §8.7.4.2.2)\n  body: %s", amfID, ranID, body)
	}
}
