// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test5GRegisterFlood(t *testing.T) {
	gnbID := mustCreateGNB(t)

	const n = 25

	supis := claimSubscribers(t, n)

	runParallel(t, n, func(i int) error {
		_, err := registerSUPI(gnbID, supis[i])
		return err
	})

	if _, err := registerSUPI(gnbID, claimSubscriber(t)); err != nil {
		t.Fatalf("fresh registration after flood failed: %v", err)
	}
}

func Test5GUECapabilityInfo_NGAPIDFuzz(t *testing.T) {
	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	cases := []struct {
		name      string
		overrides string
	}{
		{"unknown AMF-UE-NGAP-ID (0)", `"amf_ue_ngap_id_override":0`},
		{"unknown AMF-UE-NGAP-ID (2^40-1)", `"amf_ue_ngap_id_override":1099511627775`},
		{"inconsistent RAN-UE-NGAP-ID (2^32-1)", `"ran_ue_ngap_id_override":4294967295`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(
				`{"message_type":"ue_capability_info","ue_radio_capability":"0102",%s,"timeout_ms":3000}`, tc.overrides)

			status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
			if status != 200 {
				t.Fatalf("ue_capability_info: HTTP %d\n  body: %s", status, resp)
			}

			assertSpecCompliantErrorIndication(t, resp)
		})
	}
}

func Test5GServiceRequest_Replay(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	if got := jsonGet(ngap5GStep(t, gnbID, ueID, "service_request"), "ngap.message_type"); got != ngapInitialContextSetupRequest {
		t.Fatalf("first service request did not re-establish: got %q", got)
	}

	if got := jsonGet(ngap5GStep(t, gnbID, ueID, "ue_context_release_request"), "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Fatalf("release did not tear down the context: got %q", got)
	}

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","nas_count":0,"timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("replayed service_request: HTTP %d\n  body: %s", status, resp)
	}

	if got := jsonGet(resp, "ngap.message_type"); got == ngapInitialContextSetupRequest {
		t.Fatalf("AMF re-established on a SERVICE REQUEST with a stale NAS COUNT (TS 24.501 §4.4.3.5)\n  body: %s", resp)
	}
}
