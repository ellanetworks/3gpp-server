// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test4GGTPU_ICMPRoundTrip(t *testing.T) {
	enbID := createGTPUENB(t, claimENBID(), "gtpu-icmp-rt-enb", n3IPv4)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	ueIP := jsonGet(getENBUE(t, enbID, ueID), "ue_ip")
	if ueIP == "" {
		t.Fatalf("no UE IP captured from the attach accept; ue: %s", getENBUE(t, enbID, ueID))
	}

	const icmpID, icmpSeq = 4660, 7

	baseline := scrapeUPFCounters(t)

	uplink := fmt.Sprintf(`{"icmp_echo":{"dst":%q,"id":%d,"seq":%d}}`, dnResponderIP, icmpID, icmpSeq)
	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/uplink", uplink); s != 200 {
		t.Fatalf("send uplink: HTTP %d: %s", s, b)
	}

	s, dl := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":5000}`)
	if s != 200 {
		t.Fatalf("no downlink received — the UPF did not forward/return the user-plane traffic\n%s", upfDelta(t, baseline))
	}

	checks := map[string]string{
		"inner.icmp_type": "0", // Echo Reply
		"inner.src":       dnResponderIP,
		"inner.dst":       ueIP,
		"inner.icmp_id":   fmt.Sprintf("%d", icmpID),
		"inner.icmp_seq":  fmt.Sprintf("%d", icmpSeq),
	}

	for field, want := range checks {
		if got := jsonGet(dl, field); got != want {
			t.Errorf("downlink %s = %q, want %q\n  body: %s", field, got, want, dl)
		}
	}
}
