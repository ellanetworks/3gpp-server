// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Test4GUserPlane proves the default bearer carries data: a UE uplink ICMP echo
// to a data-network host round-trips back as a decapsulated downlink reply on the
// S1-U tunnel — the MME/UPF programmed the forwarding state from the attach.
func Test4GUserPlane(t *testing.T) {
	enbID := createGTPUENB(t, claimENBID(), "gtpu-enb", n3IPv4)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	const icmpID, icmpSeq = 4660, 7

	baseline := scrapeUPFCounters(t)

	uplink := fmt.Sprintf(`{"icmp_echo":{"dst":%q,"id":%d,"seq":%d}}`, dnResponderIP, icmpID, icmpSeq)
	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/uplink", uplink); s != 200 {
		t.Fatalf("send uplink: HTTP %d: %s", s, b)
	}

	s, dl := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":5000}`)
	if s != 200 {
		t.Fatalf("no downlink received — the UPF did not forward the user-plane traffic\n%s", upfDelta(t, baseline))
	}

	if got := jsonGet(dl, "inner.icmp_type"); got != "0" {
		t.Fatalf("downlink inner.icmp_type = %q, want 0 (ICMP echo reply); body: %s", got, dl)
	}

	if got := jsonGet(dl, "inner.icmp_seq"); got != fmt.Sprintf("%d", icmpSeq) {
		t.Fatalf("downlink inner.icmp_seq = %q, want %d; body: %s", got, icmpSeq, dl)
	}
}

// Test4GMultiPDNUserPlane proves an additional PDN connection carries data on its
// own bearer: an uplink ICMP echo selected by the additional bearer's EBI
// round-trips on that bearer's distinct S1-U tunnel, not the default bearer's.
func Test4GMultiPDNUserPlane(t *testing.T) {
	enbID := createGTPUENB(t, claimENBID(), "gtpu-multipdn-enb", n3IPv4)
	ueID := mustCreateENBUE(t, enbID)

	ebi := connectSecondPDN(t, enbID, ueID)

	const icmpID, icmpSeq = 4661, 9

	baseline := scrapeUPFCounters(t)

	uplink := fmt.Sprintf(`{"ebi":%s,"icmp_echo":{"dst":%q,"id":%d,"seq":%d}}`, ebi, dnResponderIP, icmpID, icmpSeq)
	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/uplink", uplink); s != 200 {
		t.Fatalf("send uplink on ebi %s: HTTP %d: %s", ebi, s, b)
	}

	s, dl := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/downlink/await",
		fmt.Sprintf(`{"ebi":%s,"timeout_ms":5000}`, ebi))
	if s != 200 {
		t.Fatalf("no downlink on the additional bearer — the UPF did not forward its user-plane traffic\n%s",
			upfDelta(t, baseline))
	}

	if got := jsonGet(dl, "inner.icmp_type"); got != "0" {
		t.Fatalf("downlink inner.icmp_type = %q, want 0 (echo reply); body: %s", got, dl)
	}

	if got := jsonGet(dl, "inner.icmp_seq"); got != fmt.Sprintf("%d", icmpSeq) {
		t.Fatalf("downlink inner.icmp_seq = %q, want %d; body: %s", got, icmpSeq, dl)
	}
}
