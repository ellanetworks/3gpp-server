// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

func getENBUE(t *testing.T, enbID, ueID string) []byte {
	t.Helper()

	status, body := doRequest(t, "GET", "/enb/"+enbID+"/ue/"+ueID, "")
	if status != 200 {
		t.Fatalf("get ue: HTTP %d: %s", status, body)
	}

	return body
}

func Test4GMultiPDNConnect(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	defaultEBI := jsonGet(getENBUE(t, enbID, ueID), "default_ebi")
	defaultIP := jsonGet(getENBUE(t, enbID, ueID), "ue_ip")

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet46"}`)

	if got := jsonGet(resp, "nas.message_type"); got != "activate_default_eps_bearer_context_request" {
		t.Fatalf("pdn connectivity: nas.message_type = %q, want activate_default_eps_bearer_context_request (TS 24.301 §6.5.1.3); body: %s", got, resp)
	}

	newEBI := jsonGet(resp, "nas.eps_bearer_identity")
	if newEBI == "" || newEBI == defaultEBI {
		t.Fatalf("additional PDN EBI = %q, want a distinct value from the default %q; body: %s", newEBI, defaultEBI, resp)
	}

	ue := getENBUE(t, enbID, ueID)
	newIP := jsonGet(ue, "bearers.0.ue_ip")
	if newIP == "" || newIP == defaultIP {
		t.Fatalf("additional PDN IP = %q, want a distinct address from the default %q; ue: %s", newIP, defaultIP, ue)
	}
}

func Test4GMultiPDNIPv6(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet6","pdn_type":2,"timeout_ms":4000}`)

	if got := jsonGet(resp, "nas.message_type"); got != "activate_default_eps_bearer_context_request" {
		t.Fatalf("IPv6 PDN: nas.message_type = %q, want activate_default_eps_bearer_context_request; body: %s", got, resp)
	}

	// The PDN address IE begins with the PDN type octet; 02 = IPv6 (TS 24.301 §9.9.4.9).
	addr := jsonGet(resp, "nas.pdn_address")
	if len(addr) < 2 || addr[:2] != "02" {
		t.Fatalf("IPv6 PDN address = %q, want a PDN type IPv6 (02…) address; body: %s", addr, resp)
	}

	// Type octet plus the 8-octet IPv6 interface identifier of octets 4 to 11 (TS 24.301 §9.9.4.9).
	if want := 2 + 2*8; len(addr) != want {
		t.Errorf("IPv6 PDN address = %q (%d hex chars), want %d: a PDN type octet and an 8-octet interface identifier (TS 24.301 §9.9.4.9); body: %s",
			addr, len(addr), want, resp)
	}
}

func connectSecondPDN(t *testing.T, enbID, ueID string) string {
	t.Helper()

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet46"}`)
	if got := jsonGet(resp, "nas.message_type"); got != "activate_default_eps_bearer_context_request" {
		t.Fatalf("connect second PDN: nas.message_type = %q, want activate_default_eps_bearer_context_request; body: %s", got, resp)
	}

	return jsonGet(resp, "nas.eps_bearer_identity")
}

func Test4GPDNDisconnect(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	ebi := connectSecondPDN(t, enbID, ueID)

	const disconnectPTI = "9"

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_disconnect","linked_ebi":`+ebi+`,"pti":`+disconnectPTI+`}`)

	if got := jsonGet(resp, "nas.message_type"); got != "deactivate_eps_bearer_context_request" {
		t.Fatalf("pdn disconnect: nas.message_type = %q, want deactivate_eps_bearer_context_request (TS 24.301 §6.5.2.3); body: %s", got, resp)
	}

	if got := jsonGet(resp, "s1ap.message_type"); got != "ERABReleaseCommand" {
		t.Fatalf("pdn disconnect: s1ap.message_type = %q, want ERABReleaseCommand (TS 36.413 §8.2.3); body: %s", got, resp)
	}

	if got := jsonGet(resp, "nas.eps_bearer_identity"); got != ebi {
		t.Fatalf("deactivated EBI = %q, want %q (the disconnected PDN); body: %s", got, ebi, resp)
	}

	if got := jsonGet(resp, "nas.bearer_pti"); got != disconnectPTI {
		t.Errorf("deactivated PTI = %q, want %q (the PTI of the PDN Disconnect Request) (TS 24.301 §6.5.2.3, §6.4.4.2); body: %s",
			got, disconnectPTI, resp)
	}

	// bearers holds the additional PDN connections only; the default PDN connection is not listed.
	if b := jsonGet(getENBUE(t, enbID, ueID), "bearers.0.ebi"); b != "" {
		t.Fatalf("additional bearer still present after disconnect: %q", b)
	}
}

func Test4GPDNConnectivityUnknownAPN(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"no-such-apn","timeout_ms":3000}`)

	if got := jsonGet(resp, "nas.message_type"); got != "pdn_connectivity_reject" {
		t.Fatalf("unknown APN: nas.message_type = %q, want pdn_connectivity_reject (TS 24.301 §6.5.1.4); body: %s", got, resp)
	}

	if c := jsonGet(resp, "nas.esm_cause"); c != "27" && c != "66" {
		t.Fatalf("unknown APN: esm_cause = %q, want 27 or 66; body: %s", c, resp)
	}
}

func Test4GPDNConnectivityInvalidPTI(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet46","pti":0,"timeout_ms":3000}`)

	if got := jsonGet(resp, "nas.message_type"); got != "pdn_connectivity_reject" {
		t.Fatalf("reserved PTI: nas.message_type = %q, want pdn_connectivity_reject (TS 24.301 §7.3.1 a)); body: %s", got, resp)
	}

	if c := jsonGet(resp, "nas.esm_cause"); c != "81" {
		t.Fatalf("reserved PTI: esm_cause = %q, want 81 (invalid PTI value); body: %s", c, resp)
	}
}

// A valid PDN Connectivity Request carries EPS bearer identity 0 in the ESM header (TS 24.301 §7.3.2 a)).
func Test4GPDNConnectivityInvalidEBI(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet46","request_ebi":5,"timeout_ms":3000}`)

	if got := jsonGet(resp, "nas.message_type"); got != "pdn_connectivity_reject" {
		t.Fatalf("invalid EBI: nas.message_type = %q, want pdn_connectivity_reject (TS 24.301 §7.3.2 a)); body: %s", got, resp)
	}

	if c := jsonGet(resp, "nas.esm_cause"); c != "43" {
		t.Fatalf("invalid EBI: esm_cause = %q, want 43 (invalid EPS bearer identity); body: %s", c, resp)
	}
}

func Test4GPDNDisconnectInvalidPTI(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	ebi := connectSecondPDN(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_disconnect","linked_ebi":`+ebi+`,"pti":0,"timeout_ms":3000}`)

	if got := jsonGet(resp, "nas.message_type"); got != "pdn_disconnect_reject" {
		t.Fatalf("reserved PTI: nas.message_type = %q, want pdn_disconnect_reject (TS 24.301 §7.3.1 b)); body: %s", got, resp)
	}

	if c := jsonGet(resp, "nas.esm_cause"); c != "81" {
		t.Fatalf("reserved PTI: esm_cause = %q, want 81 (invalid PTI value); body: %s", c, resp)
	}
}

func Test4GPDNDisconnectLastPDN(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)
	defaultEBI := jsonGet(getENBUE(t, enbID, ueID), "default_ebi")

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_disconnect","linked_ebi":`+defaultEBI+`,"timeout_ms":3000}`)

	if got := jsonGet(resp, "nas.message_type"); got != "pdn_disconnect_reject" {
		t.Fatalf("last-PDN disconnect: nas.message_type = %q, want pdn_disconnect_reject (TS 24.301 §6.5.2.4); body: %s", got, resp)
	}

	if c := jsonGet(resp, "nas.esm_cause"); c != "49" {
		t.Fatalf("last-PDN disconnect: esm_cause = %q, want 49 (last PDN disconnection not allowed); body: %s", c, resp)
	}
}

func Test4GPDNConnectivityDuplicateAPN(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	connectSecondPDN(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet46","timeout_ms":4000}`)

	switch got := jsonGet(resp, "nas.message_type"); got {
	case "activate_default_eps_bearer_context_request":
		// Accepting the request, deactivating the existing connection, is conformant (TS 24.301 §6.5.1.4.3).
	case "pdn_connectivity_reject":
		if c := jsonGet(resp, "nas.esm_cause"); c != "55" {
			t.Fatalf("duplicate APN reject: esm_cause = %q, want 55 (multiple PDN connections for a given APN not allowed); body: %s", c, resp)
		}
	default:
		t.Fatalf("duplicate APN: nas.message_type = %q, want activate_default or pdn_connectivity_reject #55 (TS 24.301 §6.5.1.4.3); body: %s", got, resp)
	}
}
