// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Test4GUEContextReleaseRequest_OutOfRangeCause is the 4G twin of
// Test5GUEContextReleaseRequest_OutOfRangeCause: a UE CONTEXT RELEASE REQUEST
// whose radio-network Cause is beyond the root ENUMERATED values is encoded via
// the CHOICE extension marker (TS 36.413 §9.2.1.3). The MME must handle it — a
// UE CONTEXT RELEASE COMMAND or an ERROR INDICATION — and must not crash.
func Test4GUEContextReleaseRequest_OutOfRangeCause(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	body := fmt.Sprintf(`{"message_type":"ue_context_release_request","release_cause":%d}`, causeRadioNetworkOutOfRange)

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", body)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
	}

	if got := jsonGet(resp, "s1ap.message_type"); got != "UEContextReleaseCommand" && got != "ErrorIndication" {
		t.Errorf("s1ap.message_type = %q, want UEContextReleaseCommand or ErrorIndication\n  body: %s", got, resp)
	}

	assertENBCoreAlive(t)
}
