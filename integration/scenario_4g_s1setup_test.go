// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Scenario tests for 4G/LTE exercise S1AP/NAS-EPS procedures against the MME.
// S1 Setup is the first procedure on an S1-MME association (TS 36.413 §8.7).

package integration_test

import (
	"testing"
)

// mustCreateENB creates a standard eNB, completes S1 Setup against the MME, and
// returns the store handle. Registers cleanup.
func mustCreateENB(t *testing.T) string {
	t.Helper()

	body := `{
		"mme_address": "10.3.0.2:36412",
		"enb_s1_address": "10.3.0.3",
		"mcc": "001", "mnc": "01",
		"tac": "0001", "enb_id": 1,
		"name": "test-enb"
	}`

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create enb: HTTP %d: %s", status, resp)
	}

	enbID := jsonGet(resp, "enb_id")
	if enbID == "" {
		t.Fatal("create enb: no enb_id in response")
	}

	t.Cleanup(func() {
		doRequest(t, "DELETE", "/enb/"+enbID, "")
	})

	return enbID
}

func Test4GScenarioS1Setup(t *testing.T) {
	enbID := mustCreateENB(t)

	t.Run("S1 Setup Response returned", func(t *testing.T) {
		status, resp := doRequest(t, "POST", "/enb", `{
			"mme_address": "10.3.0.2:36412",
			"enb_s1_address": "10.3.0.3",
			"mcc": "001", "mnc": "01",
			"tac": "0001", "enb_id": 2,
			"name": "assert-enb"
		}`)
		if status != 201 {
			t.Fatalf("create enb: HTTP %d: %s", status, resp)
		}

		id := jsonGet(resp, "enb_id")
		t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })

		if got := jsonGet(resp, "response.pdu_type"); got != "successful_outcome" {
			t.Fatalf("pdu_type = %q, want successful_outcome; body: %s", got, resp)
		}

		if got := jsonGet(resp, "response.message_type"); got != "S1SetupResponse" {
			t.Fatalf("message_type = %q, want S1SetupResponse; body: %s", got, resp)
		}

		if gummeis := jsonGet(resp, "response.s1_setup_response.served_gummeis"); gummeis == "" || gummeis == "null" || gummeis == "[]" {
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
			"enb_id": "1",
			"name":   "test-enb",
		} {
			if got := jsonGet(body, key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
	})
}
