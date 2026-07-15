// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Only one eNB can bind a given S1-U address:port, so callers must let cleanup run before reusing the same transport.
func createGTPUENB(t *testing.T, enbID int, name string, n3 n3Transport) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"mme_address": "10.3.0.2:36412",
		"enb_s1_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "0001", "enb_id": %d,
		"name": %q,
		"enable_gtpu": true, "enb_n3_address": %q
	}`, enbID, name, n3.ranN3)

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create GTP-U eNB: HTTP %d: %s", status, resp)
	}

	id := jsonGet(resp, "enb_id")
	t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })

	return id
}

func Test4GGTPUEcho(t *testing.T) {
	for _, n3 := range []n3Transport{n3IPv4, n3IPv6} {
		t.Run(n3.name, func(t *testing.T) {
			enbID := createGTPUENB(t, claimENBID(), "gtpu-echo-enb-"+n3.name, n3)

			status, body := doRequest(t, "POST", "/enb/"+enbID+"/gtpu/echo",
				fmt.Sprintf(`{"upf_ip":%q,"timeout_ms":5000}`, n3.upfN3))
			if status != 200 {
				t.Fatalf("no GTP-U Echo Response (HTTP %d) on S1-U over %s — the UPF did not answer a conformant Echo Request (TS 29.281 §7.2.1)\n  body: %s", status, n3.name, body)
			}

			if got := jsonGet(body, "echo_response"); got != "true" {
				t.Errorf("echo_response = %q over %s, want true\n  body: %s", got, n3.name, body)
			}
		})
	}
}

func Test4GGTPUWrongTEIDErrorIndication(t *testing.T) {
	enbID := createGTPUENB(t, claimENBID(), "gtpu-errind-enb", n3IPv4)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/uplink",
		fmt.Sprintf(`{"teid":%d,"icmp_echo":{"dst":%q,"id":778,"seq":1}}`, badTEID, dnResponderIP))
	if status != 200 {
		t.Fatalf("send uplink: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/enb/"+enbID+"/gtpu/error-indication/await", `{"timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("no GTP-U Error Indication for a G-PDU to an unknown TEID on S1-U (HTTP %d) — the UPF shall return one (TS 29.281 §7.3.1)\n  body: %s", status, body)
	}
}

func Test4GGTPU_UDPRoundTrip(t *testing.T) {
	enbID := createGTPUENB(t, claimENBID(), "gtpu-udp-enb", n3IPv4)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	const payloadHex = "abad1dea"

	uplink := fmt.Sprintf(`{"udp":{"dst":%q,"dst_port":%d,"payload_hex":%q}}`, dnResponderIP, udpEchoPort, payloadHex)
	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/uplink", uplink); s != 200 {
		t.Fatalf("send udp uplink: HTTP %d: %s", s, b)
	}

	s, dl := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":5000}`)
	if s != 200 {
		t.Fatal("no UDP downlink — the UPF did not forward/return UDP user-plane traffic")
	}

	checks := map[string]string{
		"inner.protocol":     "17",
		"inner.src":          dnResponderIP,
		"inner.udp_src_port": fmt.Sprintf("%d", udpEchoPort),
		"inner.payload":      payloadHex,
	}
	for field, want := range checks {
		if got := jsonGet(dl, field); got != want {
			t.Errorf("UDP downlink %s = %q, want %q\n  body: %s", field, got, want, dl)
		}
	}
}
