//go:build integration

// N3 / GTP-U user-plane: the emulated gNB terminates the data tunnel. These
// tests validate the GTP-U path (TS 29.281) and end-to-end connectivity: a UE
// uplink ICMP echo to a data-network host must round-trip back as a decapsulated
// downlink reply, proving the UPF programmed the forwarding state from the
// control-plane PDU session establishment.

package integration_test

import (
	"fmt"
	"testing"
)

// dnResponderIP is the data-network host on N6 (compose sidecar) that replies to
// ICMP echo.
const dnResponderIP = "10.6.0.10"

// upfN3IP is the UPF's N3 GTP-U endpoint (the core's data-plane address on the
// N3 network), the peer for GTP-U path management.
const upfN3IP = "10.3.0.2"

// createGTPUGnB creates a gNB that terminates the N3 GTP-U data path. Only one
// can exist at a time (it binds the N3 GTP-U port), so callers must let cleanup
// run before the next.
func createGTPUGnB(t *testing.T, gnbID, name string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"amf_address": "10.3.0.2:38412", "gnb_n2_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "000001",
		"gnb_id": %q, "name": %q, "sst": 1, "enable_gtpu": true
	}`, gnbID, name)

	status, resp := doRequest(t, "POST", "/gnb", body)
	if status != 201 {
		t.Fatalf("create gtpu gnb %s: HTTP %d: %s", gnbID, status, resp)
	}

	id := jsonGet(resp, "gnb_id")
	if id == "" {
		t.Fatalf("create gtpu gnb %s: no gnb_id: %s", gnbID, resp)
	}

	t.Cleanup(func() { doRequest(t, "DELETE", "/gnb/"+id, "") })

	return id
}

// TestGTPU_ICMPRoundTrip: a UE uplink ICMP echo to a data-network host must come
// back as a downlink ICMP echo reply, decapsulated from the N3 tunnel — proving
// the UPF forwards user-plane traffic on the tunnel established over the control
// plane.
func TestGTPU_ICMPRoundTrip(t *testing.T) {
	gnbID := createGTPUGnB(t, "00ec03", "gtpu-rt")
	ueID := establishRegisteredUEWithSUPI(t, gnbID, "imsi-001010000000001")

	// The control plane must have captured the N3 tunnel: the UPF's uplink TEID
	// and the UE's IP.
	status, body := doRequest(t, "GET", "/gnb/"+gnbID+"/ue/"+ueID+"/tunnel", "")
	if status != 200 {
		t.Fatalf("get tunnel: HTTP %d\n  body: %s", status, body)
	}

	ueIP := jsonGet(body, "ue_ip")
	if ueIP == "" {
		t.Fatalf("no UE IP captured from the establishment accept\n  body: %s", body)
	}

	if got := jsonGet(body, "ul_teid"); got == "" || got == "0" {
		t.Fatalf("no uplink TEID captured from the setup request transfer\n  body: %s", body)
	}

	const icmpID, icmpSeq = 4660, 7

	body, ok := gtpuAwaitDownlink(t, gnbID, ueID, dnResponderIP, icmpID, icmpSeq)
	if !ok {
		t.Fatalf("no downlink received — the UPF did not forward/return the user-plane traffic")
	}

	checks := map[string]string{
		"inner.icmp_type": "0", // Echo Reply
		"inner.src":       dnResponderIP,
		"inner.dst":       ueIP,
		"inner.icmp_id":   fmt.Sprintf("%d", icmpID),
		"inner.icmp_seq":  fmt.Sprintf("%d", icmpSeq),
	}

	for field, want := range checks {
		if got := jsonGet(body, field); got != want {
			t.Errorf("downlink %s = %q, want %q\n  body: %s", field, got, want, body)
		}
	}
}

// TestGTPU_Echo: a GTP-U Echo Request — sequence-number flag set, no extension
// header, the conformant path-management form — must be answered with an Echo
// Response. A GTP-U peer "shall be prepared to receive an Echo Request at any
// time and it shall reply with an Echo Response" (TS 29.281 §7.2.1); a timeout
// means the UPF dropped a conformant Echo Request.
func TestGTPU_Echo(t *testing.T) {
	gnbID := createGTPUGnB(t, "00ec04", "gtpu-echo")

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/gtpu/echo",
		fmt.Sprintf(`{"upf_ip":%q,"timeout_ms":5000}`, upfN3IP))
	if status != 200 {
		t.Fatalf("no GTP-U Echo Response (HTTP %d) — the UPF did not answer a conformant Echo Request (TS 29.281 §7.2.1)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "echo_response"); got != "true" {
		t.Errorf("echo_response = %q, want true\n  body: %s", got, body)
	}
}

// gtpuAwaitDownlink sends one uplink ICMP echo to dst and waits for the
// decapsulated downlink reply, returning the reply body and whether one arrived.
// The N3 data path is kept warm by the dn-responder keepalive (the UPF resolves
// N6 next-hops lazily and loses the first packet to an unresolved one), so a
// single round trip is deterministic: it returns as soon as the reply arrives,
// and only a genuine forwarding failure exhausts the timeout.
func gtpuAwaitDownlink(t *testing.T, gnbID, ueID, dst string, id, seq int) ([]byte, bool) {
	t.Helper()

	uplink := fmt.Sprintf(`{"icmp_echo":{"dst":%q,"id":%d,"seq":%d}}`, dst, id, seq)
	if status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/uplink", uplink); status != 200 {
		t.Fatalf("send uplink: HTTP %d\n  body: %s", status, body)
	}

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/downlink/await",
		`{"timeout_ms":5000}`)

	return body, status == 200
}

// TestGTPU_ReleaseStopsForwarding: once the PDU session is released, the UPF
// must stop forwarding the UE's user plane. The test first proves the tunnel
// forwards (an uplink ICMP echo round-trips), releases the session (TS 24.501
// §6.3.3), then replays the same uplink and requires no downlink — the UPF must
// drop it because the forwarding state was torn down.
func TestGTPU_ReleaseStopsForwarding(t *testing.T) {
	gnbID := createGTPUGnB(t, "00ec05", "gtpu-rel")
	ueID := establishRegisteredUEWithSUPI(t, gnbID, "imsi-001010000000002")

	const icmpID, icmpSeq = 0x1234, 11

	// Forwarding works while the session is up.
	if _, ok := gtpuAwaitDownlink(t, gnbID, ueID, dnResponderIP, icmpID, icmpSeq); !ok {
		t.Fatalf("no downlink before release — the tunnel should forward while the session is up")
	}

	// Release the PDU session (TS 24.501 §6.3.3).
	for _, step := range []string{"pdu_session_release_request", "pdu_session_release_complete"} {
		if status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"`+step+`"}`); status != 200 {
			t.Fatalf("%s: HTTP %d\n  body: %s", step, status, body)
		}
	}

	// Forwarding must stop: the UPF drops the user plane for the torn-down session.
	if _, ok := gtpuAwaitDownlink(t, gnbID, ueID, dnResponderIP, icmpID, icmpSeq); ok {
		t.Fatalf("a downlink arrived after the session was released — the UPF kept forwarding torn-down user plane")
	}
}
