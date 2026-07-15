// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Only one gNB can bind a given N3 address:port at a time.
func createGTPUGnB(t *testing.T, gnbID, name string, n3 n3Transport) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"amf_address": "10.3.0.2:38412", "gnb_n2_address": "10.3.0.3", "gnb_n3_address": %q,
		"mcc": "001", "mnc": "01", "tac": "000001",
		"gnb_id": %q, "name": %q, "sst": 1, "enable_gtpu": true
	}`, n3.ranN3, gnbID, name)

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

func Test5GGTPU_ICMPRoundTrip(t *testing.T) {
	gnbID := createGTPUGnB(t, "00ec03", "gtpu-rt", n3IPv4)
	ueID := establishRegisteredUEWithSUPI(t, gnbID, "imsi-001010000000001")

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

func Test5GGTPU_Echo(t *testing.T) {
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

func Test5GGTPU_ReleaseStopsForwarding(t *testing.T) {
	gnbID := createGTPUGnB(t, "00ec05", "gtpu-rel", n3IPv4)
	ueID := establishRegisteredUEWithSUPI(t, gnbID, "imsi-001010000000002")

	const icmpID, icmpSeq = 0x1234, 11

	baseline := scrapeUPFCounters(t)
	if _, ok := gtpuAwaitDownlink(t, gnbID, ueID, dnResponderIP, icmpID, icmpSeq); !ok {
		t.Fatalf("no downlink before release — the tunnel should forward while the session is up\n%s",
			upfDelta(t, baseline))
	}

	for _, step := range []string{"pdu_session_release_request", "pdu_session_release_complete"} {
		if status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			`{"message_type":"`+step+`"}`); status != 200 {
			t.Fatalf("%s: HTTP %d\n  body: %s", step, status, body)
		}
	}

	released := scrapeUPFCounters(t)
	if _, ok := gtpuAwaitDownlink(t, gnbID, ueID, dnResponderIP, icmpID, icmpSeq); ok {
		t.Fatalf("a downlink arrived after the session was released — the UPF kept forwarding torn-down user plane (TS 24.501 §6.3.3)\n%s",
			upfDelta(t, released))
	}
}

func Test5GGTPU_UDPRoundTrip(t *testing.T) {
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

func Test5GGTPU_WrongTEID_Dropped(t *testing.T) {
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

func Test5GGTPU_WrongTEID_ErrorIndication(t *testing.T) {
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
