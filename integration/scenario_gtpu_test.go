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

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/uplink",
		fmt.Sprintf(`{"icmp_echo":{"dst":%q,"id":%d,"seq":%d}}`, dnResponderIP, icmpID, icmpSeq))
	if status != 200 {
		t.Fatalf("send uplink: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/downlink/await",
		`{"timeout_ms":5000}`)
	if status != 200 {
		t.Fatalf("no downlink received (HTTP %d) — the UPF did not forward/return the user-plane traffic\n  body: %s", status, body)
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
