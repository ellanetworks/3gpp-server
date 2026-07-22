// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test4GUplinkForgedAPID(t *testing.T) {
	const forgedMMEID = 4294967000

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		fmt.Sprintf(`{"message_type":"tracking_area_update","mme_ue_s1ap_id_override":%d,"existing_connection":true,"timeout_ms":2000}`, forgedMMEID))
	if status != 200 {
		t.Fatalf("tracking_area_update with a forged MME UE S1AP ID: HTTP %d\n  body: %s", status, body)
	}

	ei := awaitENBS1AP(t, enbID, `["ErrorIndication"]`)
	if got := jsonGet(ei, "s1ap.message_type"); got != "ErrorIndication" {
		t.Fatalf("s1ap.message_type = %q, want ErrorIndication — an uplink naming an unknown UE-associated connection must draw one (TS 36.413 §10.6)\n  body: %s", got, ei)
	}

	if got := jsonGet(ei, "s1ap.mme_ue_s1ap_id"); got != fmt.Sprintf("%d", forgedMMEID) {
		t.Errorf("Error Indication mme_ue_s1ap_id = %q, want the received %d (TS 36.413 §10.6)\n  body: %s",
			got, forgedMMEID, ei)
	}

	if got := jsonGet(ei, "s1ap.cause.group"); got == "" {
		t.Errorf("Error Indication carries no Cause (TS 36.413 §10.6 requires an appropriate cause value)\n  body: %s", ei)
	}
}
