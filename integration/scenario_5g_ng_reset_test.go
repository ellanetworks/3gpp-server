// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// NG Reset (TS 38.413 §8.7.4): the gNB resets the whole NG interface or a
// subset of UE associations; the AMF answers with NG Reset Acknowledge.

package integration_test

import (
	"encoding/json"
	"strconv"
	"testing"
)

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

// On a full NG Reset the AMF releases the UE associations and answers with NG
// Reset Acknowledge (TS 38.413 §8.7.4.2.2).
func Test5GNGReset_All(t *testing.T) {
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

// For each reset connection the AMF shall include the AMF UE NGAP ID and RAN UE
// NGAP ID in the NG Reset Acknowledge's UE-associated Logical NG-connection List
// (TS 38.413 §8.7.4.2.2).
func Test5GNGReset_Partial(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

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
