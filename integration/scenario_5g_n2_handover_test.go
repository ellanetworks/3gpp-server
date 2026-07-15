// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// N2 handover (inter-gNB without Xn, TS 38.413 §8.4): a registered UE with a
// PDU session is handed over from a source gNB to a target gNB through the AMF.
// The flow is driven message-by-message across two gNB associations.

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

// A specific NGAP gNB ID lets two gNBs coexist on the same core.
func createGnBWithID(t *testing.T, gnbID, name string) string {
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

	ies, ok := ngapObj["ies"].([]any)
	if !ok {
		return 0, false
	}

	for _, ie := range ies {
		iem, ok := ie.(map[string]any)
		if !ok {
			continue
		}

		if v, ok := iem["amf_ue_ngap_id"].(float64); ok {
			return int64(v), true
		}
	}

	return 0, false
}

func ngapPDUSessionIDs(body []byte) []int64 {
	var top struct {
		NGAP struct {
			IEs []struct {
				PDUSessionIDs []int64 `json:"pdu_session_ids"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	var ids []int64
	for _, ie := range top.NGAP.IEs {
		ids = append(ids, ie.PDUSessionIDs...)
	}

	return ids
}

func ngapReleasePDUSessionIDs(body []byte) []int64 {
	var top struct {
		NGAP struct {
			IEs []struct {
				ReleasePDUSessionIDs []int64 `json:"release_pdu_session_ids"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	var ids []int64
	for _, ie := range top.NGAP.IEs {
		ids = append(ids, ie.ReleasePDUSessionIDs...)
	}

	return ids
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

// ngapAMBR returns the UE Aggregate Maximum Bit Rate in bps.
func ngapAMBR(body []byte) (dl, ul int64, ok bool) {
	var top struct {
		NGAP struct {
			IEs []struct {
				AMBR *struct {
					DL int64 `json:"dl"`
					UL int64 `json:"ul"`
				} `json:"ue_aggregate_max_bit_rate"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return 0, 0, false
	}

	for _, ie := range top.NGAP.IEs {
		if ie.AMBR != nil {
			return ie.AMBR.DL, ie.AMBR.UL, true
		}
	}

	return 0, 0, false
}

func ngapHasCause(body []byte) bool {
	var top struct {
		NGAP struct {
			IEs []struct {
				Cause *struct {
					Present string `json:"present"`
				} `json:"cause"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return false
	}

	for _, ie := range top.NGAP.IEs {
		if ie.Cause != nil && ie.Cause.Present != "" {
			return true
		}
	}

	return false
}

// The Security Context IE is surfaced via its Next Hop Chaining Count.
func ngapHasSecurityContext(body []byte) bool {
	var top struct {
		NGAP struct {
			IEs []struct {
				NCC *int64 `json:"next_hop_chaining_count"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return false
	}

	for _, ie := range top.NGAP.IEs {
		if ie.NCC != nil {
			return true
		}
	}

	return false
}

// runN2HandoverFlow drives the inter-NG-RAN N2 handover signalling flow between
// two gNBs. The message order follows TS 23.502 §4.9.1.3: preparation §4.9.1.3.2
// (Handover Required step 1 → Handover Request step 9 → Handover Request
// Acknowledge step 10) and execution §4.9.1.3.3 (Handover Command step 1 →
// Handover Notify step 5 → UE Context Release Command step 14a). The given body
// establishes the PDU session that is handed over.
func runN2HandoverFlow(t *testing.T, establishBody string) {
	t.Helper()

	sourceGNB := createGnBWithID(t, "000001", "source-gnb")
	targetGNB := createGnBWithID(t, "000002", "target-gnb")

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

	// The PDU session list, UE AMBR and Security Context are all mandatory IEs of
	// HANDOVER REQUEST (TS 38.413 §9.2.3.1); the Security Context carries the
	// NH/NCC the target derives K_gNB from (TS 33.501 §6.9).
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

	// The command must confirm the same PDU session for handover (§9.2.3.2).
	assertCarriesPDUSession(t, hoCmd, 1, "HandoverCommand")

	// The PDCP status the target needs for a lossless handover (TS 23.502
	// §4.9.1.3.3 steps 2-3).
	assertRANStatusTransferRelayed(t, sourceGNB, targetGNB, ueID, targetRanUeNgapID)

	status, body = doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_notify","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d}`,
			targetAmfID, targetRanUeNgapID))
	if status != 200 {
		t.Fatalf("handover_notify: HTTP %d\n  body: %s", status, body)
	}

	// The Notify is what makes the AMF release the source's resources (TS 23.502
	// §4.9.1.3.3 step 14a).
	rel := awaitNGAP(t, sourceGNB, ngapUEContextReleaseCommand)
	if got := jsonGet(rel, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Errorf("ngap.message_type = %q, want UEContextReleaseCommand (source released after handover)\n  body: %s", got, rel)
	}
}

func Test5GN2Handover(t *testing.T) {
	runN2HandoverFlow(t, `{"message_type":"pdu_session_establishment_request"}`)
}
