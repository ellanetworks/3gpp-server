// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// s1uUPFIP is the S-GW/UPF S1-U (N3) address the emulated eNB tunnels to.
const s1uUPFIP = "10.3.0.2"

// createGTPUENB creates an eNB that terminates the S1-U GTP-U data path.
func createGTPUENB(t *testing.T, enbID int, name string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"mme_address": "10.3.0.2:36412",
		"enb_s1_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "0001", "enb_id": %d,
		"name": %q,
		"enable_gtpu": true, "enb_n3_address": "10.3.0.3"
	}`, enbID, name)

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create GTP-U eNB: HTTP %d: %s", status, resp)
	}

	id := jsonGet(resp, "enb_id")
	t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+id, "") })

	return id
}

// Test4GGTPUEcho: a GTP-U Echo Request the eNB sends on S1-U — the path-management
// form with no extension header — must be answered with an Echo Response. A
// GTP-U peer "shall be prepared to receive an Echo Request at any time and it
// shall reply with an Echo Response" (TS 29.281 §7.2.1); a timeout means the UPF
// dropped a conformant Echo Request.
func Test4GGTPUEcho(t *testing.T) {
	enbID := createGTPUENB(t, 1, "gtpu-echo-enb")

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/gtpu/echo",
		fmt.Sprintf(`{"upf_ip":%q,"timeout_ms":5000}`, s1uUPFIP))
	if status != 200 {
		t.Fatalf("no GTP-U Echo Response (HTTP %d) on S1-U — the UPF did not answer a conformant Echo Request (TS 29.281 §7.2.1)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "echo_response"); got != "true" {
		t.Errorf("echo_response = %q, want true\n  body: %s", got, body)
	}
}

// Test4GGTPUWrongTEIDErrorIndication: a G-PDU carrying a non-zero TEID for which
// the UPF has no PDR must be answered with a GTP-U Error Indication on S1-U
// (TS 29.281 §7.3.1: the node "shall also return a GTP error indication to the
// originating node").
func Test4GGTPUWrongTEIDErrorIndication(t *testing.T) {
	enbID := createGTPUENB(t, 1, "gtpu-errind-enb")
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

// Test4GGTPU_UDPRoundTrip proves the S1-U data path carries UDP, not only ICMP: a
// UE uplink UDP datagram to the data-network responder returns as a decapsulated
// downlink datagram echoed back — the UPF forwards and NATs UDP user-plane traffic.
func Test4GGTPU_UDPRoundTrip(t *testing.T) {
	enbID := createGTPUENB(t, 1, "gtpu-udp-enb")
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	const payloadHex = "abad1dea"

	// The UPF can lose the first packet while it resolves the N6 next-hop, so retry.
	var dl []byte

	for i := 0; i < 5; i++ {
		uplink := fmt.Sprintf(`{"udp":{"dst":%q,"dst_port":%d,"payload_hex":%q}}`, dnResponderIP, udpEchoPort, payloadHex)
		if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/uplink", uplink); s != 200 {
			t.Fatalf("send udp uplink: HTTP %d: %s", s, b)
		}

		if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":2000}`); s == 200 {
			dl = b
			break
		}
	}

	if dl == nil {
		t.Fatal("no UDP downlink — the UPF did not forward/return UDP user-plane traffic")
	}

	checks := map[string]string{
		"inner.protocol":     "17", // UDP
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
