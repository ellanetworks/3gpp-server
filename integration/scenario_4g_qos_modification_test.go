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

const qosModIMSI = "001010000000104"

// The default policy seeds at 5QI 9, ARP 1, session-AMBR 200 Mbps.
func setPolicyQoS(t *testing.T, token string, var5qi, arp int) {
	t.Helper()

	body := fmt.Sprintf(`{"profile_name":"default","slice_name":"default","data_network_name":"internet","session_ambr_uplink":"200 Mbps","session_ambr_downlink":"200 Mbps","var5qi":%d,"arp":%d}`, var5qi, arp)

	req, _ := http.NewRequest("PUT", ellaAPIURL+"/api/v1/policies/default", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("set policy QoS: %v", err)
	}

	_ = resp.Body.Close()
}

func Test4GQoSModification(t *testing.T) {
	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("ella core token: %v", err)
	}

	if err := createSubscriber(token, qosModIMSI); err != nil {
		t.Fatalf("create subscriber: %v", err)
	}
	t.Cleanup(func() { deleteSubscriber(t, token, qosModIMSI) })
	t.Cleanup(func() { setPolicyQoS(t, token, 9, 1) })

	enbID := createGTPUENB(t, claimENBID(), "qos-mod-enb", n3IPv4)

	body := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000020"}`, qosModIMSI, testK, testOPc)
	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create UE: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	fullAttach(t, enbID, ueID)

	const newVar5qi, newARP = 7, 5
	setPolicyQoS(t, token, newVar5qi, newARP)

	status, body2 := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["ERABModifyRequest"],"timeout_ms":8000}`)
	if status != 200 {
		t.Fatalf("no E-RAB Modify Request after 5QI/ARP change (HTTP %d) — the MME must modify the radio bearer (TS 36.413 §8.2.2)\n  body: %s", status, body2)
	}

	checks := map[string]string{
		"s1ap.message_type":                           "ERABModifyRequest",
		"s1ap.erab_modify_items.0.qci":                fmt.Sprintf("%d", newVar5qi),
		"s1ap.erab_modify_items.0.arp_priority_level": fmt.Sprintf("%d", newARP),
		"nas.message_type":                            "modify_eps_bearer_context_request",
	}
	for field, want := range checks {
		if got := jsonGet(body2, field); got != want {
			t.Fatalf("E-RAB Modify %s = %q, want %q\n  body: %s", field, got, want, body2)
		}
	}

	if status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", `{"message_type":"modify_response"}`); status != 200 {
		t.Fatalf("modify_response: HTTP %d\n  body: %s", status, resp)
	}

	if status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", `{"message_type":"modify_eps_bearer_context_accept"}`); status != 200 {
		t.Fatalf("modify_eps_bearer_context_accept: HTTP %d\n  body: %s", status, resp)
	}

	status, relResp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		`{"message_type":"ue_context_release_request","timeout_ms":5000}`)
	if status != 200 {
		t.Fatalf("release_request: HTTP %d\n  body: %s", status, relResp)
	}

	if got := jsonGet(relResp, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("after modification, release drew s1ap.message_type = %q, want UEContextReleaseCommand — the bearer must remain usable (TS 24.301 §6.4.3.3)\n  body: %s", got, relResp)
	}
}
