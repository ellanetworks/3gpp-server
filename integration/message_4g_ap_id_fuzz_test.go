// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func Test4GAuthenticationFailure_S1APIDFuzz(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := attachChallenge(t, enbID)

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		`{"message_type":"authentication_failure","cause":20,"mme_ue_s1ap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("authentication failure hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	assertEPSErrorIndication(t, body)
}

func Test4GIdentity_S1APIDFuzz(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"attach_request","foreign_guti":true}`)
	if got := jsonGet(resp, "nas.message_type"); got != "identity_request" {
		t.Fatalf("foreign-GUTI attach: nas.message_type = %q, want identity_request (TS 24.301 §5.4.4)\n  body: %s", got, resp)
	}

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		`{"message_type":"identity_response","mme_ue_s1ap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("identity response hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	assertEPSErrorIndication(t, body)
}

func Test4GSecurityModeComplete_S1APIDFuzz(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unknown MME UE S1AP ID", `{"message_type":"security_mode_complete","mme_ue_s1ap_id_override":99999}`},
		{"inconsistent eNB UE S1AP ID", `{"message_type":"security_mode_complete","enb_ue_s1ap_id_override":99999}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID, _ := attachToSMC(t, enbID, "")

			status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", tc.body)
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
			}

			assertEPSErrorIndication(t, body)
		})
	}
}

func Test4GSecurityModeReject_S1APIDFuzz(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID, _ := attachToSMC(t, enbID, "")

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		`{"message_type":"security_mode_reject","cause":23,"mme_ue_s1ap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("security mode reject hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	assertEPSErrorIndication(t, body)
}

func Test4GAttachComplete_S1APIDFuzz(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantHTTP        int
		wantS1APMsgType string
	}{
		{
			name:            "MME UE S1AP ID = 0",
			body:            `{"message_type":"attach_complete","mme_ue_s1ap_id_override":0}`,
			wantHTTP:        200,
			wantS1APMsgType: "ErrorIndication",
		},
		{
			name:            "MME UE S1AP ID = nonexistent",
			body:            `{"message_type":"attach_complete","mme_ue_s1ap_id_override":99999}`,
			wantHTTP:        200,
			wantS1APMsgType: "ErrorIndication",
		},
		{
			name:            "eNB UE S1AP ID = 0",
			body:            `{"message_type":"attach_complete","enb_ue_s1ap_id_override":0}`,
			wantHTTP:        200,
			wantS1APMsgType: "ErrorIndication",
		},
		{
			name:            "eNB UE S1AP ID = max 24-bit",
			body:            `{"message_type":"attach_complete","enb_ue_s1ap_id_override":16777215}`,
			wantHTTP:        200,
			wantS1APMsgType: "ErrorIndication",
		},
		{
			name:            "MME UE S1AP ID = max 32-bit",
			body:            `{"message_type":"attach_complete","mme_ue_s1ap_id_override":4294967295}`,
			wantHTTP:        200,
			wantS1APMsgType: "ErrorIndication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID := mustCreateENBUE(t, enbID)

			for _, step := range []string{"attach_request", "authentication_response", "security_mode_complete"} {
				nasStep(t, enbID, ueID, step)
			}

			status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", tt.body)
			if status != tt.wantHTTP {
				t.Fatalf("HTTP %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}

			if got := jsonGet(body, "s1ap.message_type"); got != tt.wantS1APMsgType {
				t.Errorf("s1ap.message_type = %q, want %q\n  body: %s", got, tt.wantS1APMsgType, body)
			}

			if tt.wantS1APMsgType == "ErrorIndication" {
				assertEPSErrorIndication(t, body)
			}
		})
	}
}
