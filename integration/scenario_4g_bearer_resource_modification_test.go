// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// A UE-requested dedicated-bearer modification is refused with a BEARER RESOURCE
// MODIFICATION REJECT carrying an ESM cause: EPS bearer QoS is network-determined
// (TS 24.301 §6.5.4.4).
func Test4GBearerResourceModification_Rejected(t *testing.T) {
	assertBearerResourceRejected(t,
		"bearer_resource_modification_request",
		"bearer_resource_modification_reject")
}

// A UE-requested dedicated-bearer allocation is refused with a BEARER RESOURCE
// ALLOCATION REJECT carrying an ESM cause (TS 24.301 §6.5.3.4).
func Test4GBearerResourceAllocation_Rejected(t *testing.T) {
	assertBearerResourceRejected(t,
		"bearer_resource_allocation_request",
		"bearer_resource_allocation_reject")
}

func assertBearerResourceRejected(t *testing.T, requestType, rejectType string) {
	t.Helper()

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	nasBody(t, enbID, ueID, `{"message_type":"`+requestType+`","pti":1}`)

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":4000}`)
	if status != 200 {
		t.Fatalf("%s drew no reply; TS 24.301 §6.5 requires a reject with an ESM cause\n  HTTP %d body: %s", requestType, status, resp)
	}

	if got := jsonGet(resp, "nas.message_type"); got != rejectType {
		t.Fatalf("nas.message_type = %q, want %s (TS 24.301 §6.5)\n  body: %s", got, rejectType, resp)
	}

	if got := jsonGet(resp, "nas.esm_cause"); got == "" {
		t.Errorf("%s missing its mandatory ESM cause IE (TS 24.301 §9.9.4.4)\n  body: %s", rejectType, resp)
	}
}
