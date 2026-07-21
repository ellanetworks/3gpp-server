// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const dnChangeIMSI = "001010000000105"

const dnReactName = "modreact"

func setDataNetworkMTU(t *testing.T, token string, mtu int) {
	t.Helper()

	body := fmt.Sprintf(`{"name":%q,"ipv4_pool":"10.77.0.0/24","dns":"8.8.8.8","mtu":%d}`, dnReactName, mtu)

	req, _ := http.NewRequest("PUT", ellaAPIURL+"/api/v1/networking/data-networks/"+dnReactName, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("set data network MTU: %v", err)
	}

	_ = resp.Body.Close()
}

func Test4GDataNetworkChangeReactivatesBearer(t *testing.T) {
	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("ella core token: %v", err)
	}

	if err := ensureProvisioned(token, "/api/v1/networking/data-networks", dnReactName,
		fmt.Sprintf(`{"name":%q,"ipv4_pool":"10.77.0.0/24","dns":"8.8.8.8","mtu":1400}`, dnReactName)); err != nil {
		t.Fatalf("provision data network: %v", err)
	}

	if err := ensureProvisioned(token, "/api/v1/policies", dnReactName+"-policy",
		fmt.Sprintf(`{"name":%q,"profile_name":"default","slice_name":"default","data_network_name":%q,"session_ambr_uplink":"200 Mbps","session_ambr_downlink":"200 Mbps","var5qi":9,"arp":1}`, dnReactName+"-policy", dnReactName)); err != nil {
		t.Fatalf("provision policy: %v", err)
	}

	if err := createSubscriber(token, dnChangeIMSI); err != nil {
		t.Fatalf("create subscriber: %v", err)
	}
	t.Cleanup(func() { deleteSubscriber(t, token, dnChangeIMSI) })
	t.Cleanup(func() { setDataNetworkMTU(t, token, 1400) })

	enbID := createGTPUENB(t, claimENBID(), "dn-change-enb", n3IPv4)

	body := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000020"}`, dnChangeIMSI, testK, testOPc)
	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create UE: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	fullAttach(t, enbID, ueID)

	pdn := nasBody(t, enbID, ueID, fmt.Sprintf(`{"message_type":"pdn_connectivity","apn":%q}`, dnReactName))
	if got := jsonGet(pdn, "nas.message_type"); got != "activate_default_eps_bearer_context_request" {
		t.Fatalf("pdn connectivity: nas.message_type = %q, want activate_default_eps_bearer_context_request; body: %s", got, pdn)
	}

	setDataNetworkMTU(t, token, 1300)

	status, body2 := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport","ERABReleaseCommand"],"timeout_ms":8000}`)
	if status != 200 {
		t.Fatalf("no bearer reactivation after MTU change (HTTP %d) — the MME must deactivate the bearer for reactivation (TS 24.301 §6.4.4.2)\n  body: %s", status, body2)
	}

	if got := jsonGet(body2, "nas.message_type"); got != "deactivate_eps_bearer_context_request" {
		t.Fatalf("MME-initiated NAS = %q, want deactivate_eps_bearer_context_request (TS 24.301 §6.4.4.2)\n  body: %s", got, body2)
	}

	if got := jsonGet(body2, "nas.esm_cause"); got != "39" {
		t.Fatalf("deactivate esm_cause = %q, want 39 (reactivation requested, TS 24.301 §9.9.4.4)\n  body: %s", got, body2)
	}

	// The accept is mandatory for the MME to complete the deactivation (TS 24.301 §6.4.4.3).
	accept := fmt.Sprintf(`{"message_type":"deactivate_eps_bearer_context_accept","eps_bearer_identity":%s,"pti":%s}`,
		jsonGet(body2, "nas.eps_bearer_identity"), jsonGet(body2, "nas.bearer_pti"))
	if s, ab := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", accept); s != 200 {
		t.Fatalf("deactivate accept: HTTP %d\n  body: %s", s, ab)
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "ue_context_release_request"), "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("UE not usable after PDN deactivation; release_request did not yield a UEContextReleaseCommand")
	}
}
