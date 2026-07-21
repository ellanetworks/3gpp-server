// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// TS 24.301 §7.3.1 f): an ESM message other than those in items a)–e) that carries
// a reserved PTI value shall be ignored by the network. A MODIFY EPS BEARER CONTEXT
// ACCEPT has no bearer side effect when no modification is pending, so "ignore" is
// observable as the absence of any downlink.
func Test4GESMReservedPTIIgnored(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	nasBody(t, enbID, ueID, `{"message_type":"modify_eps_bearer_context_accept","pti":255,"timeout_ms":3000}`)

	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport","ErrorIndication","UEContextReleaseCommand"],"timeout_ms":1500}`); s == 200 {
		t.Fatalf("modify accept with a reserved PTI drew a %q response; TS 24.301 §7.3.1 f) requires the network to ignore the message\n  body: %s",
			jsonGet(b, "s1ap.message_type"), b)
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "ue_context_release_request"), "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("UE unusable after a reserved-PTI modify accept; release_request did not yield a UEContextReleaseCommand")
	}
}

// TS 24.301 §7.3.1 c): a BEARER RESOURCE ALLOCATION REQUEST with a reserved PTI value draws
// "a BEARER RESOURCE ALLOCATION REJECT message including ESM cause #81 'invalid PTI value'" when
// the network implements the procedure. §7.4 lets a network that does not implement the message
// type return ESM STATUS with cause #97 instead. Both are conformant; any other reply is not.
func Test4GBearerResourceAllocationReservedPTI(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	nasBody(t, enbID, ueID, `{"message_type":"bearer_resource_allocation_request","pti":255}`)

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":4000}`)
	if status != 200 {
		t.Fatalf("reserved-PTI BEARER RESOURCE ALLOCATION REQUEST drew no reply; TS 24.301 §7.3.1 c) requires a reject with ESM cause #81, or §7.4 an ESM STATUS with #97\n  HTTP %d body: %s", status, resp)
	}
	assertReservedPTIReject(t, resp, "bearer_resource_allocation_reject")
}

// TS 24.301 §7.3.1 d): as §7.3.1 c) for the BEARER RESOURCE MODIFICATION REQUEST / REJECT.
func Test4GBearerResourceModificationReservedPTI(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	nasBody(t, enbID, ueID, `{"message_type":"bearer_resource_modification_request","pti":255}`)

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":4000}`)
	if status != 200 {
		t.Fatalf("reserved-PTI BEARER RESOURCE MODIFICATION REQUEST drew no reply; TS 24.301 §7.3.1 d) requires a reject with ESM cause #81, or §7.4 an ESM STATUS with #97\n  HTTP %d body: %s", status, resp)
	}
	assertReservedPTIReject(t, resp, "bearer_resource_modification_reject")
}

// assertReservedPTIReject accepts either the §7.3.1 reject (#81) for a network that implements the
// procedure, or the §7.4 ESM STATUS (#97) for one that does not.
func assertReservedPTIReject(t *testing.T, resp []byte, rejectType string) {
	t.Helper()

	switch mt := jsonGet(resp, "nas.message_type"); mt {
	case rejectType:
		if c := jsonGet(resp, "nas.esm_cause"); c != "81" {
			t.Errorf("esm_cause = %q, want 81 (invalid PTI value, TS 24.301 §7.3.1)\n  body: %s", c, resp)
		}
	case "esm_status":
		if c := jsonGet(resp, "nas.esm_cause"); c != "97" {
			t.Errorf("esm_cause = %q, want 97 (message type not implemented, TS 24.301 §7.4)\n  body: %s", c, resp)
		}
	default:
		t.Errorf("nas.message_type = %q, want %s (#81, §7.3.1) or esm_status (#97, §7.4)\n  body: %s", mt, rejectType, resp)
	}
}

// TS 24.301 §7.3.1 e): an ESM INFORMATION RESPONSE with a reserved PTI value is ignored by a
// network that implements the procedure. An unsolicited response is unforeseen, so §7.4 also lets
// the network return ESM STATUS #97 or take no action. A reply of any other kind is not conformant.
func Test4GESMInformationResponseReservedPTI(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	nasBody(t, enbID, ueID, `{"message_type":"esm_information_response","pti":255}`)

	s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport","ErrorIndication","UEContextReleaseCommand"],"timeout_ms":1500}`)
	if s != 200 {
		return
	}
	if jsonGet(b, "nas.message_type") == "esm_status" {
		if c := jsonGet(b, "nas.esm_cause"); c != "97" {
			t.Errorf("esm_cause = %q, want 97 (message type not implemented, TS 24.301 §7.4)\n  body: %s", c, b)
		}
		return
	}
	t.Fatalf("esm_information_response with a reserved PTI drew a %q response; TS 24.301 §7.3.1 e) requires ignore, or §7.4 an ESM STATUS #97\n  body: %s",
		jsonGet(b, "s1ap.message_type"), b)
}
