// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Test4GUplinkForgedAPID sends a UE-associated uplink whose AP IDs name a logical
// connection the MME does not know.
//
// TS 36.413 §10.6: "If a node receives a message (other than the first or first
// returned messages) that includes AP ID(s) identifying a logical connection
// which is unknown to the node […] the node shall initiate an Error Indication
// procedure with inclusion of the received AP ID(s) from the peer node and an
// appropriate cause value."
//
// The UE is attached first, so the Tracking Area Update below is neither the
// first nor the first returned message of the connection; forging the MME UE
// S1AP ID makes it name a connection the MME never allocated.
func Test4GUplinkForgedAPID(t *testing.T) {
	const forgedMMEID = 4294967000

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/nas",
		fmt.Sprintf(`{"message_type":"tracking_area_update","mme_ue_s1ap_id":%d,"timeout_ms":2000}`, forgedMMEID))
	if status != 200 {
		t.Fatalf("tracking_area_update with a forged MME UE S1AP ID: HTTP %d\n  body: %s", status, body)
	}

	ei := awaitENBS1AP(t, enbID, `["ErrorIndication"]`)
	if got := jsonGet(ei, "s1ap.message_type"); got != "ErrorIndication" {
		t.Fatalf("s1ap.message_type = %q, want ErrorIndication — an uplink naming an unknown UE-associated connection must draw one (TS 36.413 §10.6)\n  body: %s", got, ei)
	}

	// §10.6 requires the Error Indication to carry the AP ID(s) received from the
	// peer, so the eNB can locally release the connection they identify.
	if got := jsonGet(ei, "s1ap.mme_ue_s1ap_id"); got != fmt.Sprintf("%d", forgedMMEID) {
		t.Errorf("Error Indication mme_ue_s1ap_id = %q, want the received %d (TS 36.413 §10.6)\n  body: %s",
			got, forgedMMEID, ei)
	}

	// A cause value is mandatory in an ERROR INDICATION carrying no Criticality
	// Diagnostics (TS 36.413 §9.1.6.6 / §8.7.2).
	if got := jsonGet(ei, "s1ap.cause.group"); got == "" {
		t.Errorf("Error Indication carries no Cause (TS 36.413 §10.6 requires an appropriate cause value)\n  body: %s", ei)
	}
}
