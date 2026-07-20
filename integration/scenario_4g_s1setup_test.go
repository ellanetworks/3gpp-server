// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func mustCreateENB(t *testing.T) string {
	t.Helper()

	return createENBWithID(t, claimENBID(), "test-enb")
}

func Test4GScenarioS1Setup(t *testing.T) {
	stateENBID := claimENBID()
	enbID := createENBWithID(t, stateENBID, "test-enb")

	t.Run("S1 Setup Response returned", func(t *testing.T) {
		status, resp := doRequest(t, "POST", "/enb", fmt.Sprintf(`{
			"mme_address": "10.3.0.2:36412",
			"enb_s1_address": "10.3.0.3",
			"mcc": "001", "mnc": "01",
			"tac": "0001", "enb_id": "%x",
			"name": "assert-enb"
		}`, claimENBID()))
		if status != 201 {
			t.Fatalf("create enb: HTTP %d: %s", status, resp)
		}

		id := jsonGet(resp, "enb_id")
		t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })

		if got := jsonGet(resp, "s1_setup_response.pdu_type"); got != "successful_outcome" {
			t.Fatalf("pdu_type = %q, want successful_outcome; body: %s", got, resp)
		}

		if got := jsonGet(resp, "s1_setup_response.message_type"); got != "S1SetupResponse" {
			t.Fatalf("message_type = %q, want S1SetupResponse; body: %s", got, resp)
		}

		if gummeis := jsonGet(resp, "s1_setup_response.served_gummeis"); gummeis == "" || gummeis == "null" || gummeis == "[]" {
			t.Fatalf("served_gummeis is empty; body: %s", resp)
		}
	})

	t.Run("eNB state reflects creation", func(t *testing.T) {
		status, body := doRequest(t, "GET", "/enb/"+enbID, "")
		if status != 200 {
			t.Fatalf("HTTP %d: %s", status, body)
		}

		for key, want := range map[string]string{
			"mcc":    "001",
			"mnc":    "01",
			"tac":    "0001",
			"enb_id": fmt.Sprintf("%x", stateENBID),
			"name":   "test-enb",
		} {
			if got := jsonGet(body, key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
	})
}
