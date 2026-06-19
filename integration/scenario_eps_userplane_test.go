// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// TestEPSUserPlane proves the default bearer carries data: a UE uplink ICMP echo
// to a data-network host round-trips back as a decapsulated downlink reply on the
// S1-U tunnel — the MME/UPF programmed the forwarding state from the attach.
func TestEPSUserPlane(t *testing.T) {
	body := `{
		"mme_address": "10.3.0.2:36412",
		"enb_s1_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "0001", "enb_id": 1,
		"name": "gtpu-enb",
		"enable_gtpu": true, "enb_n3_address": "10.3.0.3"
	}`

	status, resp := doRequest(t, "POST", "/enb", body)
	if status != 201 {
		t.Fatalf("create GTP-U eNB: HTTP %d: %s", status, resp)
	}

	enbID := jsonGet(resp, "enb_id")
	t.Cleanup(func() { doRequest(t, "DELETE", "/enb/"+enbID, "") })

	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	const icmpID, icmpSeq = 4660, 7

	// The UPF can lose the first packet while it resolves the N6 next-hop, so retry.
	var dl []byte

	for i := 0; i < 5; i++ {
		uplink := fmt.Sprintf(`{"icmp_echo":{"dst":%q,"id":%d,"seq":%d}}`, dnResponderIP, icmpID, icmpSeq)
		if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/uplink", uplink); s != 200 {
			t.Fatalf("send uplink: HTTP %d: %s", s, b)
		}

		if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":2000}`); s == 200 {
			dl = b
			break
		}
	}

	if dl == nil {
		t.Fatal("no downlink received — the UPF did not forward the user-plane traffic")
	}

	if got := jsonGet(dl, "inner.icmp_type"); got != "0" {
		t.Fatalf("downlink inner.icmp_type = %q, want 0 (ICMP echo reply); body: %s", got, dl)
	}

	if got := jsonGet(dl, "inner.icmp_seq"); got != fmt.Sprintf("%d", icmpSeq) {
		t.Fatalf("downlink inner.icmp_seq = %q, want %d; body: %s", got, icmpSeq, dl)
	}
}
