// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

const (
	testK   = "00112233445566778899aabbccddeeff"
	testOPc = "63bfa50ee6523365ff14c1f45f88737d"
)

func mustCreateENBUE(t *testing.T, enbID string) string {
	t.Helper()

	imsi := claimSubscriber(t)[len("imsi-"):]
	body := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000000"}`, imsi, testK, testOPc)

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create ue: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	if ueID == "" {
		t.Fatalf("create ue: no ue_id: %s", resp)
	}

	return ueID
}

func nasStep(t *testing.T, enbID, ueID, messageType string) []byte {
	t.Helper()

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/nas",
		fmt.Sprintf(`{"message_type":%q}`, messageType))
	if status != 200 {
		t.Fatalf("%s: HTTP %d: %s", messageType, status, resp)
	}

	return resp
}

func Test4GScenarioAttach(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	t.Run("attach request yields EPS-AKA challenge", func(t *testing.T) {
		resp := nasStep(t, enbID, ueID, "attach_request")

		if got := jsonGet(resp, "nas.message_type"); got != "authentication_request" {
			t.Fatalf("nas.message_type = %q, want authentication_request; body: %s", got, resp)
		}

		if jsonGet(resp, "nas.rand") == "" || jsonGet(resp, "nas.autn") == "" {
			t.Fatalf("Authentication Request missing RAND/AUTN (TS 24.301 §8.2.7); body: %s", resp)
		}
	})

	t.Run("auth response yields integrity-verified Security Mode Command", func(t *testing.T) {
		resp := nasStep(t, enbID, ueID, "authentication_response")

		if got := jsonGet(resp, "nas.message_type"); got != "security_mode_command" {
			t.Fatalf("nas.message_type = %q, want security_mode_command; body: %s", got, resp)
		}

		if got := jsonGet(resp, "mac_verified"); got != "true" {
			t.Fatalf("Security Mode Command NAS-MAC did not verify under independent keys; body: %s", resp)
		}

		// TS 33.401 §5.1.4.1 / TS 24.301 §5.4.3.3: EIA0 is only for emergency/RLOS.
		if got := jsonGet(resp, "nas.integrity_algorithm"); got == "0" || got == "" {
			t.Fatalf("MME selected NAS integrity algorithm %q for a normal attach; want non-EIA0; body: %s", got, resp)
		}

		// The MME must replay the UE's security capabilities verbatim against
		// bidding-down (TS 24.301 §5.4.3.2); the UE advertised EEA0/1/2 + EIA0/1/2.
		if got := jsonGet(resp, "nas.replayed_ue_security_capabilities"); got != "e0e0" {
			t.Fatalf("replayed UE security capabilities = %q, want e0e0; body: %s", got, resp)
		}
	})

	t.Run("security mode complete yields Attach Accept with GUTI and bearer", func(t *testing.T) {
		resp := nasStep(t, enbID, ueID, "security_mode_complete")

		if got := jsonGet(resp, "s1ap.message_type"); got != "InitialContextSetupRequest" {
			t.Fatalf("s1ap.message_type = %q, want InitialContextSetupRequest; body: %s", got, resp)
		}

		if got := jsonGet(resp, "nas.message_type"); got != "attach_accept" {
			t.Fatalf("nas.message_type = %q, want attach_accept; body: %s", got, resp)
		}

		if jsonGet(resp, "nas.guti.m_tmsi") == "" {
			t.Fatalf("Attach Accept missing GUTI (TS 24.301 §5.5.1.2.4); body: %s", resp)
		}

		if jsonGet(resp, "nas.eps_bearer_identity") == "" {
			t.Fatalf("Attach Accept missing default bearer; body: %s", resp)
		}
	})

	t.Run("attach complete", func(t *testing.T) {
		nasStep(t, enbID, ueID, "attach_complete")
	})
}
