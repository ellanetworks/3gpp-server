// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// When a UE re-establishes on a new S1 connection while an old one is still up, the MME
// must release the superseded connection toward the eNB with a UE CONTEXT RELEASE
// COMMAND (TS 36.413 §8.3.3.1), not silently drop it.
func Test4GSupersededConnectionReleased(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"tracking_area_update","reestablish":true,"timeout_ms":8000}`)
	if got := jsonGet(resp, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("superseded S1 connection: s1ap.message_type = %q, want UEContextReleaseCommand (TS 36.413 §8.3.3.1)\n  body: %s", got, resp)
	}

	assertENBCoreAlive(t)
}
