// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

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

func Test4GUplinkNASTransportS1APIDFuzz(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown MME-UE-S1AP-ID (0, never allocated)",
			body: `{"message_type":"inject_nas","mme_ue_s1ap_id_override":0,"raw_nas_pdu":"00","timeout_ms":3000}`,
		},
		{
			name: "unknown MME-UE-S1AP-ID (2^32-1, never allocated)",
			body: `{"message_type":"inject_nas","mme_ue_s1ap_id_override":4294967295,"raw_nas_pdu":"00","timeout_ms":3000}`,
		},
		{
			name: "inconsistent eNB-UE-S1AP-ID (valid MME ID, forged eNB ID)",
			body: `{"message_type":"inject_nas","enb_ue_s1ap_id_override":16777215,"raw_nas_pdu":"00","timeout_ms":3000}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := nasBody(t, enbID, ueID, tc.body)
			assertEPSErrorIndication(t, resp)
		})
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

var s1apIDFuzzCases = []struct {
	name      string
	overrides string
}{
	{"unknown MME-UE-S1AP-ID (0)", `"mme_ue_s1ap_id_override":0`},
	{"unknown MME-UE-S1AP-ID (2^32-1)", `"mme_ue_s1ap_id_override":4294967295`},
	{"inconsistent eNB-UE-S1AP-ID", `"enb_ue_s1ap_id_override":16777215`},
}

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
