// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// gnbDrainDownlinks consumes any buffered downlink replies so a following
// negative test does not pick up a stale one.
func gnbDrainDownlinks(t *testing.T, gnbID, ueID string) {
	t.Helper()

	for {
		if s, _ := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":300}`); s != 200 {
			return
		}
	}
}

// Test5GUserPlaneSourceSpoofing checks the UPF drops uplink user data whose inner
// source IP is not the UE's allocated address (UE source anti-spoofing, GSMA
// security baseline). A rogue UE-A sends traffic with victim UE-B's source IP: if
// the UPF forwards it, the data-network reply un-NATs to B's address and is
// delivered to B's tunnel — proving A impersonated B's IP. The UPF must instead
// drop A's spoofed-source uplink. Mirrors Test4GUserPlaneSourceSpoofing on the N3
// GTP-U path.
func Test5GUserPlaneSourceSpoofing(t *testing.T) {
	gnbID := createGTPUGnB(t, "00ec05", "gtpu-spoof", n3IPv4)

	ueA := establishRegisteredUEWithSUPI(t, gnbID, testSUPI(1))
	ueB := establishRegisteredUEWithSUPI(t, gnbID, testSUPI(2))

	_, bTunnel := doRequest(t, "GET", "/gnb/"+gnbID+"/ue/"+ueB+"/tunnel", "")

	victimIP := jsonGet(bTunnel, "ue_ip")
	if victimIP == "" {
		t.Fatal("could not determine victim UE-B's IP")
	}

	// Baseline: UE-A's legitimate user plane works, so a later "no delivery to B"
	// reflects the UPF dropping the spoof, not a broken data path.
	if _, ok := gtpuAwaitDownlink(t, gnbID, ueA, dnResponderIP, 0x10, 1); !ok {
		t.Fatal("UE-A baseline round-trip failed")
	}

	gnbDrainDownlinks(t, gnbID, ueA)
	gnbDrainDownlinks(t, gnbID, ueB)

	for i := 0; i < 4; i++ {
		up := fmt.Sprintf(`{"icmp_echo":{"dst":%q,"id":4444,"seq":66},"src":%q}`, dnResponderIP, victimIP)
		if s, b := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueA+"/uplink", up); s != 200 {
			t.Fatalf("uplink: HTTP %d: %s", s, b)
		}

		if s, b := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueB+"/downlink/await", `{"timeout_ms":1500}`); s == 200 {
			t.Fatalf("UPF forwarded UE-A's spoofed-source uplink (source = UE-B's IP %s) and delivered the reply to UE-B — no UE source-address anti-spoofing; a UE can impersonate another subscriber's IP\n  downlink: %s", victimIP, b)
		}
	}
}
