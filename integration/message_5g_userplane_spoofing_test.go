// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Buffered replies are drained so a following negative assertion cannot pick up a stale one.
func gnbDrainDownlinks(t *testing.T, gnbID, ueID string) {
	t.Helper()

	for {
		if s, _ := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":300}`); s != 200 {
			return
		}
	}
}

// A forwarded spoof shows up as the data-network reply un-NATing to UE-B's
// address and reaching UE-B's tunnel.
func Test5GUserPlaneSourceSpoofing(t *testing.T) {
	gnbID := createGTPUGNB(t, "00ec09", "gtpu-spoof", n3IPv4)

	ueA := establishRegisteredUEWithSUPI(t, gnbID, testSUPI(1))
	ueB := establishRegisteredUEWithSUPI(t, gnbID, testSUPI(2))

	_, bTunnel := doRequest(t, "GET", "/gnb/"+gnbID+"/ue/"+ueB+"/tunnel", "")

	victimIP := jsonGet(bTunnel, "ue_ip")
	if victimIP == "" {
		t.Fatal("could not determine victim UE-B's IP")
	}

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
