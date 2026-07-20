// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

func createGNBWithID(t *testing.T, gnbID, name string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"amf_address": "10.3.0.2:38412", "gnb_n2_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "000001",
		"gnb_id": "%s", "name": "%s", "sst": 1
	}`, gnbID, name)

	status, resp := doRequest(t, "POST", "/gnb", body)
	if status != 201 {
		t.Fatalf("create gnb %s: HTTP %d: %s", gnbID, status, resp)
	}

	id := jsonGet(resp, "gnb_id")
	if id == "" {
		t.Fatalf("create gnb %s: no gnb_id in response: %s", gnbID, resp)
	}

	t.Cleanup(func() { doRequest(t, "DELETE", "/gnb/"+id, "") })

	return id
}

func awaitNGAP(t *testing.T, gnbID string, messageTypes ...string) []byte {
	t.Helper()

	mt, _ := json.Marshal(messageTypes)
	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/await",
		fmt.Sprintf(`{"message_types": %s, "timeout_ms": 5000}`, mt))
	if status != 200 {
		t.Fatalf("await %v on gnb %s: HTTP %d\n  body: %s", messageTypes, gnbID, status, body)
	}

	return body
}

func ngapFirstAmfUeNgapID(body []byte) (int64, bool) {
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return 0, false
	}

	ngapObj, ok := top["ngap"].(map[string]any)
	if !ok {
		return 0, false
	}

	if v, ok := ngapObj["amf_ue_ngap_id"].(float64); ok {
		return int64(v), true
	}

	return 0, false
}

func ngapPDUSessionIDs(body []byte) []int64 {
	var top struct {
		NGAP struct {
			PDUSessionIDs []int64 `json:"pdu_session_ids"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	return top.NGAP.PDUSessionIDs
}

func ngapReleasePDUSessionIDs(body []byte) []int64 {
	var top struct {
		NGAP struct {
			ReleasePDUSessionIDs []int64 `json:"release_pdu_session_ids"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	return top.NGAP.ReleasePDUSessionIDs
}

func sameInt64Set(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}

	seen := make(map[int64]int, len(a))
	for _, v := range a {
		seen[v]++
	}

	for _, v := range b {
		seen[v]--
	}

	for _, n := range seen {
		if n != 0 {
			return false
		}
	}

	return true
}

func assertCarriesPDUSession(t *testing.T, body []byte, want int64, context string) {
	t.Helper()
	assertCarriesPDUSessions(t, body, []int64{want}, context)
}

func assertCarriesPDUSessions(t *testing.T, body []byte, want []int64, context string) {
	t.Helper()

	if ids := ngapPDUSessionIDs(body); !sameInt64Set(ids, want) {
		t.Errorf("%s: PDU session list = %v, want %v\n  body: %s", context, ids, want, body)
	}
}

func ngapAMBR(body []byte) (dl, ul int64, ok bool) {
	var top struct {
		NGAP struct {
			AMBR *struct {
				DL int64 `json:"dl"`
				UL int64 `json:"ul"`
			} `json:"ue_aggregate_max_bit_rate"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return 0, 0, false
	}

	if top.NGAP.AMBR != nil {
		return top.NGAP.AMBR.DL, top.NGAP.AMBR.UL, true
	}

	return 0, 0, false
}

func ngapHasCause(body []byte) bool {
	var top struct {
		NGAP struct {
			Cause *struct {
				Group string `json:"group"`
			} `json:"cause"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return false
	}

	return top.NGAP.Cause != nil && top.NGAP.Cause.Group != ""
}

// The Security Context IE is surfaced only via its Next Hop Chaining Count.
func ngapHasSecurityContext(body []byte) bool {
	var top struct {
		NGAP struct {
			NCC *int64 `json:"next_hop_chaining_count"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return false
	}

	return top.NGAP.NCC != nil
}

// Drives an inter-NG-RAN N2 handover, preparation then execution (TS 23.502 §4.9.1.3).
func runN2HandoverFlow(t *testing.T, establishBody string) {
	t.Helper()

	sourceGNB := createGNBWithID(t, "000001", "source-gnb")
	targetGNB := createGNBWithID(t, "000002", "target-gnb")

	ueID := mustCreateUE(t, sourceGNB)
	doRegistrationFlow(t, sourceGNB, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap", establishBody)
	if status != 200 {
		t.Fatalf("pdu_session_establishment_request: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap",
		`{"message_type":"handover_required","target_gnb_id":"000002"}`)
	if status != 200 {
		t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
	}

	hoReq := awaitNGAP(t, targetGNB, ngapHandoverRequest)
	if got := jsonGet(hoReq, "ngap.message_type"); got != ngapHandoverRequest {
		t.Fatalf("ngap.message_type = %q, want HandoverRequest (TS 38.413 §8.4.2.2)\n  body: %s", got, hoReq)
	}

	assertCarriesPDUSession(t, hoReq, 1, "HandoverRequest")

	if dl, ul, ok := ngapAMBR(hoReq); !ok || dl == 0 || ul == 0 {
		t.Errorf("HandoverRequest UE AMBR missing or zero: dl=%d ul=%d present=%v\n  body: %s", dl, ul, ok, hoReq)
	}

	if !ngapHasSecurityContext(hoReq) {
		t.Errorf("HandoverRequest missing Security Context (mandatory, TS 38.413 §9.2.3.1)\n  body: %s", hoReq)
	}

	targetAmfID, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	const targetRanUeNgapID = 100
	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":9000,"dl_ip":"10.3.0.3"}]}`,
			targetAmfID, targetRanUeNgapID))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	hoCmd := awaitNGAP(t, sourceGNB, ngapHandoverCommand)
	if got := jsonGet(hoCmd, "ngap.message_type"); got != ngapHandoverCommand {
		t.Fatalf("ngap.message_type = %q, want HandoverCommand (TS 38.413 §8.4.1.2)\n  body: %s", got, hoCmd)
	}

	assertCarriesPDUSession(t, hoCmd, 1, "HandoverCommand")

	assertRANStatusTransferRelayed(t, sourceGNB, targetGNB, ueID, targetRanUeNgapID)

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_notify","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d}`,
			targetAmfID, targetRanUeNgapID))
	if status != 200 {
		t.Fatalf("handover_notify: HTTP %d\n  body: %s", status, body)
	}

	rel := awaitNGAP(t, sourceGNB, ngapUEContextReleaseCommand)
	if got := jsonGet(rel, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Errorf("ngap.message_type = %q, want UEContextReleaseCommand (source released after handover)\n  body: %s", got, rel)
	}
}

func Test5GN2Handover(t *testing.T) {
	runN2HandoverFlow(t, `{"message_type":"pdu_session_establishment_request"}`)
}
