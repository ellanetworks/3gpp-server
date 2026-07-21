// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// 5GS decouples the PDU session from registration, so the Initial Context Setup
// Request that reactivates an idle UE carries the UE-AMBR aggregated from its
// sessions. The twin of Test4GInitialContextSetup_UEAMBR (the 4G attach-time ICS);
// the E-RAB/PDU-session setup-list transport address is asserted on the standalone
// PDUSessionResourceSetupRequest (Test5GPDUSessionResourceSetup_TransportLayerAddress).
func Test5GInitialContextSetup_UEAMBR(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, ics := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 200 {
		t.Fatalf("service_request: HTTP %d\n  body: %s", status, ics)
	}

	if got := jsonGet(ics, "ngap.message_type"); got != ngapInitialContextSetupRequest {
		t.Fatalf("service_request: ngap.message_type = %q, want InitialContextSetupRequest\n  body: %s", got, ics)
	}

	if dl := jsonGet(ics, "ngap.ue_aggregate_max_bit_rate.dl"); dl == "" || dl == "0" {
		t.Fatalf("ICS Request UE-AMBR dl = %q, want a non-zero provisioned value (TS 38.413 §9.3.1.58)\n  body: %s", dl, ics)
	}

	if ul := jsonGet(ics, "ngap.ue_aggregate_max_bit_rate.ul"); ul == "" || ul == "0" {
		t.Fatalf("ICS Request UE-AMBR ul = %q, want a non-zero provisioned value (TS 38.413 §9.3.1.58)\n  body: %s", ul, ics)
	}
}
