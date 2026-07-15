// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Distinct values, so the relayed container can be compared field by field.
const (
	statusDRBID    = 3
	statusULPDCPSN = 42
	statusULHFN    = 7
	statusDLPDCPSN = 99
	statusDLHFN    = 3
)

func ngapRANStatusTransfer(body []byte) (map[string]any, bool) {
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, false
	}

	ngapObj, ok := top["ngap"].(map[string]any)
	if !ok {
		return nil, false
	}

	ies, ok := ngapObj["ies"].([]any)
	if !ok {
		return nil, false
	}

	for _, ie := range ies {
		iem, ok := ie.(map[string]any)
		if !ok {
			continue
		}

		if c, ok := iem["ran_status_transfer"].(map[string]any); ok {
			return c, true
		}
	}

	return nil, false
}

func ngapFirstRanUeNgapID(body []byte) (int64, bool) {
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

		if v, ok := iem["ran_ue_ngap_id"].(float64); ok {
			return int64(v), true
		}
	}

	return 0, false
}

// assertRANStatusTransferRelayed drives the RAN status transfer of an in-progress
// N2 handover. Per TS 38.413 §8.4.7.2 the AMF conveys the source's transparent
// container (§9.3.1.108: per-DRB UL/DL COUNT, §8.4.6.2) to the target unchanged,
// addressed to the target's UE association (§9.2.3.14).
//
// The handover must already be prepared (Handover Request Acknowledge sent):
// §8.4.7.3 lets a target ignore the message when no prepared handover exists.
func assertRANStatusTransferRelayed(t *testing.T, sourceGNB, targetGNB, ueID string, targetRanUeNgapID int64) {
	t.Helper()

	body := fmt.Sprintf(
		`{"message_type":"ran_status_transfer","status_transfer_drbs":[{"drb_id":%d,"ul_pdcp_sn":%d,"ul_hfn":%d,"dl_pdcp_sn":%d,"dl_hfn":%d}]}`,
		statusDRBID, statusULPDCPSN, statusULHFN, statusDLPDCPSN, statusDLHFN)

	status, resp := doRequest(t, "POST", "/gnb/"+sourceGNB+"/ue/"+ueID+"/ngap", body)
	if status != 200 {
		t.Fatalf("ran_status_transfer: HTTP %d\n  body: %s", status, resp)
	}

	dl := awaitNGAP(t, targetGNB, ngapDownlinkRANStatusTransfer)
	if got := jsonGet(dl, "ngap.message_type"); got != ngapDownlinkRANStatusTransfer {
		t.Fatalf("ngap.message_type = %q, want DownlinkRANStatusTransfer — the AMF must relay the source's RAN status to the target (TS 38.413 §8.4.7.2)\n  body: %s", got, dl)
	}

	if got, ok := ngapFirstRanUeNgapID(dl); !ok || got != targetRanUeNgapID {
		t.Errorf("DownlinkRANStatusTransfer RAN UE NGAP ID = %d (present=%v), want the target's %d (TS 38.413 §9.2.3.14)\n  body: %s",
			got, ok, targetRanUeNgapID, dl)
	}

	container, ok := ngapRANStatusTransfer(dl)
	if !ok {
		t.Fatalf("DownlinkRANStatusTransfer carries no RAN Status Transfer Transparent Container (mandatory, TS 38.413 §9.2.3.14)\n  body: %s", dl)
	}

	drbs, ok := container["drbs_subject_to_status_transfer"].([]any)
	if !ok || len(drbs) != 1 {
		t.Fatalf("relayed DRBs subject to status transfer = %v, want the 1 DRB the source reported (TS 38.413 §8.4.6.2)\n  body: %s", container, dl)
	}

	drb, ok := drbs[0].(map[string]any)
	if !ok {
		t.Fatalf("relayed DRB is not an object: %v\n  body: %s", drbs[0], dl)
	}

	num := func(path ...string) (float64, bool) {
		cur := drb
		for _, p := range path[:len(path)-1] {
			next, ok := cur[p].(map[string]any)
			if !ok {
				return 0, false
			}

			cur = next
		}

		v, ok := cur[path[len(path)-1]].(float64)

		return v, ok
	}

	checks := []struct {
		path []string
		want float64
	}{
		{[]string{"drb_id"}, statusDRBID},
		{[]string{"ul_count", "pdcp_sn"}, statusULPDCPSN},
		{[]string{"ul_count", "hfn"}, statusULHFN},
		{[]string{"dl_count", "pdcp_sn"}, statusDLPDCPSN},
		{[]string{"dl_count", "hfn"}, statusDLHFN},
	}

	for _, c := range checks {
		got, ok := num(c.path...)
		if !ok || got != c.want {
			t.Errorf("relayed container %v = %v (present=%v), want %v — the AMF must convey the RAN Status Transfer Transparent Container to the target unchanged (TS 38.413 §8.4.7.2, §9.3.1.108)\n  body: %s",
				c.path, got, ok, c.want, dl)
		}
	}
}
