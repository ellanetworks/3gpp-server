// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// A UE with two bearers switches both in one PATH SWITCH REQUEST (TS 36.413 §8.4.4).
func Test4GPathSwitchMultipleERABs(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	secondEBI := connectSecondPDN(t, enbID, ueID)
	defaultEBI := jsonGet(getENBUE(t, enbID, ueID), "default_ebi")

	mme, enb := enbUES1APIDs(t, enbID, ueID)

	erabs := fmt.Sprintf(`[{"id":%s,"dl_teid":9001,"dl_ip":"10.3.0.3"},{"id":%s,"dl_teid":9002,"dl_ip":"10.3.0.3"}]`, defaultEBI, secondEBI)
	resp := sendENBPathSwitchReq(t, enbID, mme, enb, erabs, "")

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestAcknowledge" {
		t.Fatalf("multi-E-RAB path switch: s1ap.message_type = %q, want PathSwitchRequestAcknowledge (TS 36.413 §8.4.4)\n  body: %s", got, resp)
	}

	if got := jsonGet(resp, "s1ap.security_context.next_hop_chaining_count"); got != "2" {
		t.Errorf("multi-E-RAB path switch ack NCC = %q, want 2 (TS 33.401 §7.2.8.4.3)\n  body: %s", got, resp)
	}
}
