// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Test4GUECapabilityInfoReplay checks the MME stores the UE radio capability
// reported via UE Capability Info Indication and replays it in a later Initial
// Context Setup Request (TS 23.401 §5.11.2), so the eNB need not re-fetch it.
func Test4GUECapabilityInfoReplay(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	const radioCap = "aabbccddee"

	nasBody(t, enbID, ueID, fmt.Sprintf(`{"message_type":"ue_capability_info","ue_radio_capability":%q}`, radioCap))

	nasStep(t, enbID, ueID, "release_request")

	sr := nasStep(t, enbID, ueID, "service_request")
	if got := jsonGet(sr, "s1ap.message_type"); got != "InitialContextSetupRequest" {
		t.Fatalf("service_request: s1ap.message_type = %q, want InitialContextSetupRequest; body: %s", got, sr)
	}

	if got := jsonGet(sr, "s1ap.ue_radio_capability"); got != radioCap {
		t.Fatalf("MME did not replay the UE radio capability (TS 23.401 §5.11.2): got %q, want %s; body: %s", got, radioCap, sr)
	}
}
