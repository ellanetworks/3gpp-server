// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ellanetworks/core/nas/eps"
)

const sessionModIMSI = "001010000000103"

// The default policy seeds at 5QI 9, ARP 1, session-AMBR 200 Mbps.
func setPolicyAMBR(t *testing.T, token, ul, dl string) {
	t.Helper()

	body := fmt.Sprintf(`{"profile_name":"default","slice_name":"default","data_network_name":"internet","session_ambr_uplink":%q,"session_ambr_downlink":%q,"var5qi":9,"arp":1}`, ul, dl)

	req, _ := http.NewRequest("PUT", ellaAPIURL+"/api/v1/policies/default", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("set policy AMBR: %v", err)
	}

	_ = resp.Body.Close()
}

func Test4GSessionAMBRModification(t *testing.T) {
	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("ella core token: %v", err)
	}

	if err := createSubscriber(token, sessionModIMSI); err != nil {
		t.Fatalf("create subscriber: %v", err)
	}
	t.Cleanup(func() { deleteSubscriber(t, token, sessionModIMSI) })
	t.Cleanup(func() { setPolicyAMBR(t, token, "200 Mbps", "200 Mbps") })

	enbID := createGTPUENB(t, claimENBID(), "sess-mod-enb", n3IPv4)

	body := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000020"}`, sessionModIMSI, testK, testOPc)
	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create UE: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	fullAttach(t, enbID, ueID)

	const newAMBR = "50 Mbps"
	setPolicyAMBR(t, token, newAMBR, newAMBR)

	status, body2 := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":8000}`)
	if status != 200 {
		t.Fatalf("no Downlink NAS Transport after session-AMBR change (HTTP %d) — the MME must modify the bearer (TS 24.301 §6.4.3)\n  body: %s", status, body2)
	}

	if got := jsonGet(body2, "nas.message_type"); got != "modify_eps_bearer_context_request" {
		t.Fatalf("MME-initiated NAS = %q, want modify_eps_bearer_context_request (TS 24.301 §6.4.3)\n  body: %s", got, body2)
	}

	wantAMBR := hex.EncodeToString(eps.APNAMBRFromBitsPerSecond(50_000_000, 50_000_000).Marshal())
	if got := jsonGet(body2, "nas.apn_ambr"); got != wantAMBR {
		t.Fatalf("Modify EPS Bearer Context Request apn_ambr = %q, want %q (50 Mbps, TS 24.301 §9.9.4.2)\n  body: %s", got, wantAMBR, body2)
	}

	// The accept is mandatory for the MME to commit the modification and stop T3486 (TS 24.301 §6.4.3.3).
	accept := fmt.Sprintf(`{"message_type":"modify_eps_bearer_context_accept","eps_bearer_identity":%s,"pti":%s}`,
		jsonGet(body2, "nas.eps_bearer_identity"), jsonGet(body2, "nas.bearer_pti"))
	if s, ab := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", accept); s != 200 {
		t.Fatalf("modify accept: HTTP %d\n  body: %s", s, ab)
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "ue_context_release_request"), "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("UE not usable after bearer modification; release_request did not yield a UEContextReleaseCommand")
	}
}
