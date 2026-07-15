// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Test4GUserPlaneSourceSpoofing checks the UPF drops uplink user data whose
// inner source IP is not the UE's allocated address (UE source anti-spoofing,
// GSMA security baseline). A rogue UE-A sends traffic with victim UE-B's source
// IP: if the UPF forwards it, the data-network reply un-NATs to B's address and
// is delivered to B's tunnel — proving A impersonated B's IP. The UPF must
// instead drop A's spoofed-source uplink.
func Test4GUserPlaneSourceSpoofing(t *testing.T) {
	enbID := createGTPUENB(t, claimENBID(), "gtpu-enb", n3IPv4)

	ueA := createENBUEWithIMSI(t, enbID, testSUPI(1)[len("imsi-"):])
	fullAttach(t, enbID, ueA)

	ueB := createENBUEWithIMSI(t, enbID, testSUPI(2)[len("imsi-"):])
	fullAttach(t, enbID, ueB)

	_, bState := doRequest(t, "GET", "/enb/"+enbID+"/ue/"+ueB, "")

	victimIP := jsonGet(bState, "ue_ip")
	if victimIP == "" {
		t.Fatal("could not determine victim UE-B's IP")
	}

	// Baseline: UE-A's legitimate user plane works, so a later "no delivery to B"
	// reflects the UPF dropping the spoof, not a broken data path.
	baseline := scrapeUPFCounters(t)
	if !uplinkRoundTrips(t, enbID, ueA, nil, 0x10, 1) {
		t.Fatalf("UE-A baseline round-trip failed\n%s", upfDelta(t, baseline))
	}

	drainDownlinks(t, enbID, ueA)
	drainDownlinks(t, enbID, ueB)

	spoof := scrapeUPFCounters(t)

	up := fmt.Sprintf(`{"icmp_echo":{"dst":%q,"id":4444,"seq":66},"src":%q}`, dnResponderIP, victimIP)
	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueA+"/uplink", up); s != 200 {
		t.Fatalf("uplink: HTTP %d: %s", s, b)
	}

	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueB+"/downlink/await", `{"timeout_ms":5000}`); s == 200 {
		t.Fatalf("UPF forwarded UE-A's spoofed-source uplink (source = UE-B's IP %s) and delivered the reply to UE-B — no UE source-address anti-spoofing; a UE can impersonate another subscriber's IP\n  downlink: %s\n%s", victimIP, b, upfDelta(t, spoof))
	}
}
