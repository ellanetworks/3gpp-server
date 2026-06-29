// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// getENBUE fetches a UE's resource as raw JSON for assertion (ue_ip, bearers, …).
func getENBUE(t *testing.T, enbID, ueID string) []byte {
	t.Helper()

	status, body := doRequest(t, "GET", "/enb/"+enbID+"/ue/"+ueID, "")
	if status != 200 {
		t.Fatalf("get ue: HTTP %d: %s", status, body)
	}

	return body
}

// TestEPSMultiPDNConnect drives a UE-requested additional PDN connection: after
// attach (default APN), the UE requests connectivity to a second APN. Per
// TS 24.301 §6.5.1.3 the MME activates a new default EPS bearer with a distinct
// EPS bearer identity and a distinct IP address — a second, independent PDN
// connection.
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

	// The second PDN must carry its own IP, distinct from the default bearer's.
	ue := getENBUE(t, enbID, ueID)
	newIP := jsonGet(ue, "bearers.0.ue_ip")
	if newIP == "" || newIP == defaultIP {
		t.Fatalf("additional PDN IP = %q, want a distinct address from the default %q; ue: %s", newIP, defaultIP, ue)
	}
}

// TestEPSMultiPDNIPv6 checks an additional PDN connection with PDN type IPv6 is
// assigned an IPv6 address: after an IPv4 default attach, the UE requests an
// IPv6 PDN to an IPv6 data network. Per TS 24.301 §9.9.4.9 the Activate Default
// PDN address carries the PDN type IPv6 (octet 2) and the 8-octet interface
// identifier.
func Test4GMultiPDNIPv6(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet6","pdn_type":2,"timeout_ms":4000}`)

	if got := jsonGet(resp, "nas.message_type"); got != "activate_default_eps_bearer_context_request" {
		t.Fatalf("IPv6 PDN: nas.message_type = %q, want activate_default_eps_bearer_context_request; body: %s", got, resp)
	}

	// The PDN address IE begins with the PDN type octet (TS 24.301 §9.9.4.9):
	// 02 = IPv6.
	if addr := jsonGet(resp, "nas.pdn_address"); len(addr) < 2 || addr[:2] != "02" {
		t.Fatalf("IPv6 PDN address = %q, want a PDN type IPv6 (02…) address; body: %s", addr, resp)
	}
}

// connectSecondPDN attaches a UE and opens a second PDN connection to internet46,
// returning the UE handle and the additional bearer's EPS bearer identity.
func connectSecondPDN(t *testing.T, enbID, ueID string) string {
	t.Helper()

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet46"}`)
	if got := jsonGet(resp, "nas.message_type"); got != "activate_default_eps_bearer_context_request" {
		t.Fatalf("connect second PDN: nas.message_type = %q, want activate_default_eps_bearer_context_request; body: %s", got, resp)
	}

	return jsonGet(resp, "nas.eps_bearer_identity")
}

// TestEPSPDNDisconnect drives a UE-requested PDN disconnect of an additional PDN
// connection. Per TS 24.301 §6.5.2.3 the MME deactivates the PDN's bearer with a
// Deactivate EPS Bearer Context Request; the UE's default PDN connection stays up.
func Test4GPDNDisconnect(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	ebi := connectSecondPDN(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_disconnect","linked_ebi":`+ebi+`}`)

	if got := jsonGet(resp, "nas.message_type"); got != "deactivate_eps_bearer_context_request" {
		t.Fatalf("pdn disconnect: nas.message_type = %q, want deactivate_eps_bearer_context_request (TS 24.301 §6.5.2.3); body: %s", got, resp)
	}

	// Disconnecting an additional PDN while the UE stays connected releases the
	// radio bearer via an E-RAB Release Command (TS 23.401 §5.10.3, TS 36.413 §8.2.3).
	if got := jsonGet(resp, "s1ap.message_type"); got != "ERABReleaseCommand" {
		t.Fatalf("pdn disconnect: s1ap.message_type = %q, want ERABReleaseCommand (TS 36.413 §8.2.3); body: %s", got, resp)
	}

	if got := jsonGet(resp, "nas.eps_bearer_identity"); got != ebi {
		t.Fatalf("deactivated EBI = %q, want %q (the disconnected PDN); body: %s", got, ebi, resp)
	}

	// The default PDN connection must remain: only the additional bearer is gone.
	if b := jsonGet(getENBUE(t, enbID, ueID), "bearers.0.ebi"); b != "" {
		t.Fatalf("additional bearer still present after disconnect: %q", b)
	}
}

// TestEPSPDNConnectivityUnknownAPN checks the MME rejects a PDN connection to an
// APN it does not provision: per TS 24.301 §6.5.1.4 it returns a PDN Connectivity
// Reject with ESM cause #27 "missing or unknown APN" (or #66 "requested APN not
// supported in current RAT and PLMN combination").
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

// TestEPSPDNConnectivityInvalidPTI checks the MME rejects a PDN Connectivity
// Request that carries a reserved PTI value (0). Per TS 24.301 §7.3.1 a) the MME
// shall respond with a PDN Connectivity Reject including ESM cause #81 "invalid
// PTI value".
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

// TestEPSPDNConnectivityInvalidEBI checks the MME rejects a PDN Connectivity
// Request whose ESM-header EPS bearer identity is non-zero (an assigned value;
// a valid request uses 0). Per TS 24.301 §7.3.2 a) the MME shall respond with a
// PDN Connectivity Reject including ESM cause #43 "invalid EPS bearer identity".
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

// TestEPSPDNDisconnectInvalidPTI checks the MME rejects a PDN Disconnect Request
// carrying a reserved PTI value (0). Per TS 24.301 §7.3.1 b) the MME shall respond
// with a PDN Disconnect Reject including ESM cause #81 "invalid PTI value".
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

// TestEPSPDNDisconnectLastPDN checks the MME refuses to disconnect the only PDN
// connection. Per TS 24.301 §6.5.2.4, when EMM-REGISTERED without PDN connection
// is not supported, the MME returns a PDN Disconnect Reject with ESM cause #49
// "last PDN disconnection not allowed".
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

// TestEPSPDNConnectivityDuplicateAPN checks the MME's handling of a second PDN
// connection request to an APN already connected. Per TS 24.301 §6.5.1.4.3 the
// network may either accept it (deactivating the existing connection) or reject
// it with ESM cause #55 "multiple PDN connections for a given APN not allowed" —
// both are conformant, so either outcome is accepted (but not a silent drop).
func Test4GPDNConnectivityDuplicateAPN(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	connectSecondPDN(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet46","timeout_ms":4000}`)

	switch got := jsonGet(resp, "nas.message_type"); got {
	case "activate_default_eps_bearer_context_request":
		// Accepted (re-established) — conformant.
	case "pdn_connectivity_reject":
		if c := jsonGet(resp, "nas.esm_cause"); c != "55" {
			t.Fatalf("duplicate APN reject: esm_cause = %q, want 55 (multiple PDN connections for a given APN not allowed); body: %s", c, resp)
		}
	default:
		t.Fatalf("duplicate APN: nas.message_type = %q, want activate_default or pdn_connectivity_reject #55 (TS 24.301 §6.5.1.4.3); body: %s", got, resp)
	}
}
