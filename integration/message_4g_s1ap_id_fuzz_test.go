// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// assertEPSErrorIndication asserts a response is a spec-compliant S1AP Error
// Indication for a UE-associated AP-ID error: the message carries a Cause and
// echoes both the MME-UE-S1AP-ID and the eNB-UE-S1AP-ID (TS 36.413 §8.7.2.2).
func assertEPSErrorIndication(t *testing.T, body []byte) {
	t.Helper()

	if got := jsonGet(body, "s1ap.message_type"); got != "ErrorIndication" {
		t.Errorf("s1ap.message_type = %q, want ErrorIndication (TS 36.413 §10.6); body: %s", got, body)
		return
	}

	if g := jsonGet(body, "s1ap.cause.group"); g == "" {
		t.Errorf("ErrorIndication missing mandatory Cause IE (TS 36.413 §8.7.2.2); body: %s", body)
	}

	if mme, enb := jsonGet(body, "s1ap.mme_ue_s1ap_id"), jsonGet(body, "s1ap.enb_ue_s1ap_id"); mme == "" || enb == "" {
		t.Errorf("ErrorIndication must echo both MME and eNB UE S1AP IDs for UE-associated signalling (TS 36.413 §8.7.2.2); body: %s", body)
	}
}

// Test4GUplinkNASTransportS1APIDFuzz mutates the UE S1AP IDs of an Uplink NAS
// Transport sent on an established association. Per TS 36.413 §10.6, a message
// carrying AP ID(s) that identify a logical connection unknown to the MME (an
// unallocated MME-UE-S1AP-ID, or an MME-UE-S1AP-ID paired with an inconsistent
// eNB-UE-S1AP-ID) obliges the MME to initiate the Error Indication procedure —
// never to silently drop the message nor route it by the MME-UE-S1AP-ID alone.
func Test4GUplinkNASTransportS1APIDFuzz(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	cases := []struct {
		name string
		body string
	}{
		{
			// The MME allocates MME-UE-S1AP-IDs from a non-zero base, so 0 was
			// never assigned to any UE: an unknown MME-UE-S1AP-ID.
			name: "unknown MME-UE-S1AP-ID (0, never allocated)",
			body: `{"message_type":"inject_nas","mme_ue_s1ap_id":0,"raw_nas_pdu":"00","timeout_ms":3000}`,
		},
		{
			name: "unknown MME-UE-S1AP-ID (2^32-1, never allocated)",
			body: `{"message_type":"inject_nas","mme_ue_s1ap_id":4294967295,"raw_nas_pdu":"00","timeout_ms":3000}`,
		},
		{
			// A valid MME-UE-S1AP-ID paired with an eNB-UE-S1AP-ID the eNB never
			// used for this UE: an inconsistent AP-ID pair.
			name: "inconsistent eNB-UE-S1AP-ID (valid MME ID, forged eNB ID)",
			body: `{"message_type":"inject_nas","enb_ue_s1ap_id":16777215,"raw_nas_pdu":"00","timeout_ms":3000}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := nasBody(t, enbID, ueID, tc.body)
			assertEPSErrorIndication(t, resp)
		})
	}

	// The MME must remain healthy after the AP-ID fuzzing: a fresh UE still attaches.
	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// s1apIDFuzzCases are the forged-AP-ID variants reused across UE-associated
// eNB-originated messages: an unallocated MME-UE-S1AP-ID and a valid
// MME-UE-S1AP-ID paired with an inconsistent eNB-UE-S1AP-ID (24-bit max). Each
// obliges the MME to answer with an Error Indication (TS 36.413 §10.6).
var s1apIDFuzzCases = []struct {
	name      string
	overrides string
}{
	{"unknown MME-UE-S1AP-ID (0)", `"mme_ue_s1ap_id":0`},
	{"unknown MME-UE-S1AP-ID (2^32-1)", `"mme_ue_s1ap_id":4294967295`},
	{"inconsistent eNB-UE-S1AP-ID", `"enb_ue_s1ap_id":16777215`},
}

// Test4GUECapabilityInfoS1APIDFuzz fuzzes the UE S1AP IDs of a UE Capability
// Info Indication on an established association. Per TS 36.413 §10.6 the MME
// must reject an unknown or inconsistent AP ID with an Error Indication rather
// than store the radio capability against a UE context.
func Test4GUECapabilityInfoS1APIDFuzz(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	for _, tc := range s1apIDFuzzCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := nasBody(t, enbID, ueID, fmt.Sprintf(
				`{"message_type":"ue_capability_info","ue_radio_capability":"0102",%s,"timeout_ms":3000}`, tc.overrides))
			assertEPSErrorIndication(t, resp)
		})
	}
}

// Test4GUEContextReleaseRequestS1APIDFuzz fuzzes the UE S1AP IDs of a UE
// Context Release Request. Per TS 36.413 §10.6 an unknown or inconsistent AP ID
// must draw an Error Indication, never a UE Context Release Command that would
// tear down another UE's connection.
func Test4GUEContextReleaseRequestS1APIDFuzz(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	for _, tc := range s1apIDFuzzCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := nasBody(t, enbID, ueID, fmt.Sprintf(
				`{"message_type":"release_request",%s,"timeout_ms":3000}`, tc.overrides))

			if got := jsonGet(resp, "s1ap.message_type"); got == "UEContextReleaseCommand" {
				t.Fatalf("MME issued a Release Command for a forged AP ID, tearing down a UE context (TS 36.413 §10.6); body: %s", resp)
			}

			assertEPSErrorIndication(t, resp)
		})
	}
}
