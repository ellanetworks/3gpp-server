// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// gtpuENBAttach creates a GTP-U eNB, attaches a UE, and confirms a baseline uplink
// round-trip works (so a later "no downlink" is meaningful). Returns enbID, ueID.
func gtpuENBAttach(t *testing.T) (string, string) {
	t.Helper()

	enbID := createGTPUENB(t, claimENBID(), "gtpu-enb", n3IPv4)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	baseline := scrapeUPFCounters(t)
	if !uplinkRoundTrips(t, enbID, ueID, nil, 0x100, 1) {
		t.Fatalf("baseline user-plane round-trip failed; cannot evaluate negatives\n%s", upfDelta(t, baseline))
	}

	drainDownlinks(t, enbID, ueID)

	return enbID, ueID
}

// uplinkRoundTrips sends one uplink ICMP echo (with an optional TEID override)
// and reports whether a decapsulated downlink reply arrived. It returns as soon
// as the reply arrives; only a genuine forwarding failure exhausts the timeout.
func uplinkRoundTrips(t *testing.T, enbID, ueID string, teid *uint32, id, seq int) bool {
	t.Helper()

	teidField := ""
	if teid != nil {
		teidField = fmt.Sprintf(`,"teid":%d`, *teid)
	}

	up := fmt.Sprintf(`{"icmp_echo":{"dst":%q,"id":%d,"seq":%d}%s}`, dnResponderIP, id, seq, teidField)
	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/uplink", up); s != 200 {
		t.Fatalf("send uplink: HTTP %d: %s", s, b)
	}

	s, _ := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":5000}`)

	return s == 200
}

// drainDownlinks consumes any buffered downlink replies so a following negative
// test does not pick up a stale one.
func drainDownlinks(t *testing.T, enbID, ueID string) {
	t.Helper()

	for {
		if s, _ := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":300}`); s != 200 {
			return
		}
	}
}

// Test4GUserPlaneWrongTEID checks the UPF does not forward user data sent on an
// uplink TEID it never allocated (an invalid bearer).
func Test4GUserPlaneWrongTEID(t *testing.T) {
	enbID, ueID := gtpuENBAttach(t)

	bogus := uint32(0xDEADBEEF)

	before := scrapeUPFCounters(t)
	if uplinkRoundTrips(t, enbID, ueID, &bogus, 0x101, 2) {
		t.Fatalf("UPF forwarded uplink user data sent on an invalid TEID\n%s", upfDelta(t, before))
	}
}

// Test4GUserPlanePostRelease checks the UPF stops forwarding downlink to a
// released eNB bearer: after an S1 release, an uplink that elicits a reply must
// not come back to the (now idle) eNB — it is buffered for paging instead.
func Test4GUserPlanePostRelease(t *testing.T) {
	enbID, ueID := gtpuENBAttach(t)

	nasStep(t, enbID, ueID, "release_request")

	before := scrapeUPFCounters(t)
	if uplinkRoundTrips(t, enbID, ueID, nil, 0x102, 3) {
		t.Fatalf("UPF forwarded downlink to a released eNB bearer (should buffer for paging)\n%s", upfDelta(t, before))
	}
}

// Test4GUserPlaneDetachStopsForwarding is the full-teardown counterpart to
// Test4GUserPlanePostRelease. A normal Detach deactivates the UE's EPS bearer and
// the S-GW/P-GW release its context (TS 23.401 §5.3.8.2.1), so the UPF must stop
// forwarding the UE's user plane entirely — not buffer it as it does for an idle
// S1 release. A replayed uplink that still round-trips means the UPF kept
// forwarding a torn-down bearer.
func Test4GUserPlaneDetachStopsForwarding(t *testing.T) {
	enbID, ueID := gtpuENBAttach(t)

	if got := jsonGet(nasStep(t, enbID, ueID, "detach_request"), "nas.message_type"); got != "detach_accept" {
		t.Fatalf("detach: nas.message_type = %q, want detach_accept (TS 24.301 §5.5.2.2.2)", got)
	}

	before := scrapeUPFCounters(t)
	if uplinkRoundTrips(t, enbID, ueID, nil, 0x103, 4) {
		t.Fatalf("UPF forwarded UE user plane after detach — a torn-down EPS bearer must stop forwarding (TS 23.401 §5.3.8.2.1)\n%s",
			upfDelta(t, before))
	}
}
