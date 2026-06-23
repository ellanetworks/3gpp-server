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

	body := `{
		"mme_address": "10.3.0.2:36412", "enb_s1_address": "10.3.0.3",
		"mcc": "001", "mnc": "01", "tac": "0001", "enb_id": 1, "name": "gtpu-enb",
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

	if !uplinkRoundTrips(t, enbID, ueID, nil, 0x100, 1) {
		t.Fatal("baseline user-plane round-trip failed; cannot evaluate negatives")
	}

	drainDownlinks(t, enbID, ueID)

	return enbID, ueID
}

// uplinkRoundTrips sends an uplink ICMP echo (with an optional TEID override) and
// reports whether a decapsulated downlink reply arrived, retrying for the UPF's
// first-packet N6 resolution loss.
func uplinkRoundTrips(t *testing.T, enbID, ueID string, teid *uint32, id, seq int) bool {
	t.Helper()

	teidField := ""
	if teid != nil {
		teidField = fmt.Sprintf(`,"teid":%d`, *teid)
	}

	for i := 0; i < 4; i++ {
		up := fmt.Sprintf(`{"icmp_echo":{"dst":%q,"id":%d,"seq":%d}%s}`, dnResponderIP, id, seq, teidField)
		if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/uplink", up); s != 200 {
			t.Fatalf("send uplink: HTTP %d: %s", s, b)
		}

		if s, _ := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/downlink/await", `{"timeout_ms":1500}`); s == 200 {
			return true
		}
	}

	return false
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

// TestEPSUserPlaneWrongTEID checks the UPF does not forward user data sent on an
// uplink TEID it never allocated (an invalid bearer).
func Test4GUserPlaneWrongTEID(t *testing.T) {
	enbID, ueID := gtpuENBAttach(t)

	bogus := uint32(0xDEADBEEF)
	if uplinkRoundTrips(t, enbID, ueID, &bogus, 0x101, 2) {
		t.Fatal("UPF forwarded uplink user data sent on an invalid TEID")
	}
}

// TestEPSUserPlanePostRelease checks the UPF stops forwarding downlink to a
// released eNB bearer: after an S1 release, an uplink that elicits a reply must
// not come back to the (now idle) eNB — it is buffered for paging instead.
func Test4GUserPlanePostRelease(t *testing.T) {
	enbID, ueID := gtpuENBAttach(t)

	nasStep(t, enbID, ueID, "release_request")

	if uplinkRoundTrips(t, enbID, ueID, nil, 0x102, 3) {
		t.Fatal("UPF forwarded downlink to a released eNB bearer (should buffer for paging)")
	}
}
