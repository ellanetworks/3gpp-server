// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

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

// n3Transport selects the IP family of the N3 GTP-U tunnel between the emulated
// gNB and the UPF. N2/SCTP stays IPv4; only the GTP-U transport varies.
type n3Transport struct {
	name  string // subtest label
	gnbN3 string // the gNB's N3 bind/source address
	upfN3 string // the UPF's N3 address (GTP-U peer)
}

var (
	n3IPv4 = n3Transport{name: "n3v4", gnbN3: "10.3.0.3", upfN3: "10.3.0.2"}
	n3IPv6 = n3Transport{name: "n3v6", gnbN3: "fd00:3::3", upfN3: "fd00:3::2"}
)

// createGTPUGnB creates a gNB that terminates the N3 GTP-U data path over the
// given transport family. Only one gNB can bind a given N3 address:port, so
// callers must let cleanup run before reusing the same transport.
func createGTPUGnB(t *testing.T, gnbID, name string, n3 n3Transport) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"amf_address": "10.3.0.2:38412", "gnb_n2_address": "10.3.0.3", "gnb_n3_address": %q,
		"mcc": "001", "mnc": "01", "tac": "000001",
		"gnb_id": %q, "name": %q, "sst": 1, "enable_gtpu": true
	}`, n3.gnbN3, gnbID, name)

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
	gnbID := createGTPUGnB(t, "00ec03", "gtpu-rt", n3IPv4)
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
// Response over both IPv4 and IPv6 N3 transport. A GTP-U peer "shall be prepared
// to receive an Echo Request at any time and it shall reply with an Echo
// Response" (TS 29.281 §7.2.1); a timeout means the UPF dropped a conformant
// Echo Request.
func TestGTPU_Echo(t *testing.T) {
	cases := []struct {
		n3    n3Transport
		gnbID string
	}{
		{n3IPv4, "00ec04"},
		{n3IPv6, "00ec4a"},
	}

	for _, tc := range cases {
		t.Run(tc.n3.name, func(t *testing.T) {
			gnbID := createGTPUGnB(t, tc.gnbID, "gtpu-echo-"+tc.n3.name, tc.n3)

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/gtpu/echo",
				fmt.Sprintf(`{"upf_ip":%q,"timeout_ms":5000}`, tc.n3.upfN3))
			if status != 200 {
				t.Fatalf("no GTP-U Echo Response (HTTP %d) over %s — the UPF did not answer a conformant Echo Request (TS 29.281 §7.2.1)\n  body: %s", status, tc.n3.name, body)
			}

			if got := jsonGet(body, "echo_response"); got != "true" {
				t.Errorf("echo_response = %q over %s, want true\n  body: %s", got, tc.n3.name, body)
			}
		})
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
	gnbID := createGTPUGnB(t, "00ec05", "gtpu-rel", n3IPv4)
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

// udpEchoPort is the port the dn-responder echoes UDP datagrams on (socat).
const udpEchoPort = 7

// TestGTPU_UDPRoundTrip: a UE uplink UDP datagram to the data network must come
// back as a decapsulated downlink datagram echoed by the responder — proving the
// UPF forwards and NATs UDP user-plane traffic, not only ICMP.
func TestGTPU_UDPRoundTrip(t *testing.T) {
	gnbID := createGTPUGnB(t, "00ec06", "gtpu-udp", n3IPv4)
	ueID := establishRegisteredUEWithSUPI(t, gnbID, "imsi-001010000000003")

	const payloadHex = "abad1dea"

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/uplink",
		fmt.Sprintf(`{"udp":{"dst":%q,"dst_port":%d,"payload_hex":%q}}`, dnResponderIP, udpEchoPort, payloadHex))
	if status != 200 {
		t.Fatalf("send udp uplink: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":5000}`)
	if status != 200 {
		t.Fatalf("no UDP downlink (HTTP %d) — the UPF did not forward/return UDP user-plane traffic\n  body: %s", status, body)
	}

	checks := map[string]string{
		"inner.protocol":     "17", // UDP
		"inner.src":          dnResponderIP,
		"inner.udp_src_port": fmt.Sprintf("%d", udpEchoPort),
		"inner.payload":      payloadHex,
	}
	for field, want := range checks {
		if got := jsonGet(body, field); got != want {
			t.Errorf("UDP downlink %s = %q, want %q\n  body: %s", field, got, want, body)
		}
	}
}

// badTEID is a non-zero TEID with no PDR at the UPF.
const badTEID = 0xFFFFFFFE

// TestGTPU_WrongTEID_Dropped: a G-PDU carrying a TEID for which the UPF has no
// PDR must be discarded, not forwarded (TS 29.281 §7.3.1) — no downlink results.
func TestGTPU_WrongTEID_Dropped(t *testing.T) {
	gnbID := createGTPUGnB(t, "00ec07", "gtpu-badteid", n3IPv4)
	ueID := establishRegisteredUEWithSUPI(t, gnbID, "imsi-001010000000004")

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/uplink",
		fmt.Sprintf(`{"teid":%d,"icmp_echo":{"dst":%q,"id":777,"seq":1}}`, badTEID, dnResponderIP))
	if status != 200 {
		t.Fatalf("send uplink: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":3000}`)
	if status == 200 {
		t.Fatalf("a downlink arrived for a G-PDU sent to an unknown TEID — the UPF must discard it (TS 29.281 §7.3.1)\n  body: %s", body)
	}
}

// TestGTPU_WrongTEID_ErrorIndication: a G-PDU carrying a non-zero TEID for which
// the UPF has no PDR must be answered with a GTP-U Error Indication (TS 29.281
// §7.3.1: the node "shall also return a GTP error indication to the originating
// node").
func TestGTPU_WrongTEID_ErrorIndication(t *testing.T) {
	gnbID := createGTPUGnB(t, "00ec08", "gtpu-errind", n3IPv4)
	ueID := establishRegisteredUEWithSUPI(t, gnbID, "imsi-001010000000005")

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/uplink",
		fmt.Sprintf(`{"teid":%d,"icmp_echo":{"dst":%q,"id":778,"seq":1}}`, badTEID, dnResponderIP))
	if status != 200 {
		t.Fatalf("send uplink: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/gtpu/error-indication/await", `{"timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("no GTP-U Error Indication for a G-PDU to an unknown TEID (HTTP %d) — the UPF shall return one (TS 29.281 §7.3.1)\n  body: %s", status, body)
	}
}
