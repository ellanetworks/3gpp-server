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

const dn5GChangeIMSI = "001010000000106"

const dn5GReactName = "modreact5g"

func setDataNetworkMTUNamed(t *testing.T, token, name string, mtu int) {
	t.Helper()

	body := fmt.Sprintf(`{"name":%q,"ipv4_pool":"10.78.0.0/24","dns":"8.8.8.8","mtu":%d}`, name, mtu)

	req, _ := http.NewRequest("PUT", ellaAPIURL+"/api/v1/networking/data-networks/"+name, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("set data network MTU: %v", err)
	}

	_ = resp.Body.Close()
}

// TS 24.501 §6.3.x: a data-network configuration change makes the network release
// the affected PDU session with 5GSM cause #39 (reactivation requested). The twin
// of the 4G Bearer-reactivation-on-DN-change test.
func Test5GDataNetworkChangeReleasesSession(t *testing.T) {
	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("ella core token: %v", err)
	}

	if err := ensureProvisioned(token, "/api/v1/networking/data-networks", dn5GReactName,
		fmt.Sprintf(`{"name":%q,"ipv4_pool":"10.78.0.0/24","dns":"8.8.8.8","mtu":1400}`, dn5GReactName)); err != nil {
		t.Fatalf("provision data network: %v", err)
	}

	if err := ensureProvisioned(token, "/api/v1/policies", dn5GReactName+"-policy",
		fmt.Sprintf(`{"name":%q,"profile_name":"default","slice_name":"default","data_network_name":%q,"session_ambr_uplink":"200 Mbps","session_ambr_downlink":"200 Mbps","var5qi":9,"arp":1}`, dn5GReactName+"-policy", dn5GReactName)); err != nil {
		t.Fatalf("provision policy: %v", err)
	}

	if err := createSubscriber(token, dn5GChangeIMSI); err != nil {
		t.Fatalf("create subscriber: %v", err)
	}
	t.Cleanup(func() { deleteSubscriber(t, token, dn5GChangeIMSI) })
	t.Cleanup(func() { setDataNetworkMTUNamed(t, token, dn5GReactName, 1400) })

	gnbID := createGTPUGNB(t, "00ec39", "dn-change-gnb", n3IPv4)

	ueBody := fmt.Sprintf(`{
		"supi": "imsi-%s",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": %q,
		"routing_indicator": "0", "protection_scheme": "0", "public_key_id": "0"
	}`, dn5GChangeIMSI, dn5GReactName)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue", ueBody)
	if status != 201 {
		t.Fatalf("create UE: HTTP %d: %s", status, resp)
	}
	ueID := jsonGet(resp, "ue_id")

	doRegistrationFlow(t, gnbID, ueID)

	_, est := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if got := jsonGet(est, "nas.inner_nas_message_type"); got != nasPDUSessionEstablishmentAccept {
		t.Fatalf("pdu session establishment: inner = %q, want pdu_session_establishment_accept; body: %s", got, est)
	}

	setDataNetworkMTUNamed(t, token, dn5GReactName, 1300)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":8000}`)
	if status != 200 {
		t.Fatalf("no session release after MTU change (HTTP %d) — the network must release the PDU session for reactivation (TS 24.501 §6.3.x)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.inner_nas_message_type"); got != nasPDUSessionReleaseCommand {
		t.Fatalf("network-initiated NAS = %q, want pdu_session_release_command (TS 24.501 §6.3.3)\n  body: %s", got, body)
	}

	if got := jsonGet(body, "nas.5gsm_cause"); got != "39" {
		t.Fatalf("release 5gsm_cause = %q, want 39 (reactivation requested, TS 24.501 §9.11.4.2)\n  body: %s", got, body)
	}
}
