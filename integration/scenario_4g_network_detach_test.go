// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"net/http"
	"testing"
)

const networkDetachIMSI = "001010000000102"

func deleteSubscriber(t *testing.T, token, imsi string) {
	t.Helper()

	req, _ := http.NewRequest("DELETE", ellaAPIURL+"/api/v1/subscribers/"+imsi, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete subscriber %s: %v", imsi, err)
	}

	_ = resp.Body.Close()
}

func Test4GNetworkInitiatedDetach(t *testing.T) {
	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("ella core token: %v", err)
	}

	if err := createSubscriber(token, networkDetachIMSI); err != nil {
		t.Fatalf("create subscriber: %v", err)
	}
	t.Cleanup(func() {
		if err := createSubscriber(token, networkDetachIMSI); err != nil {
			t.Errorf("restore subscriber %s: %v", networkDetachIMSI, err)
		}
	})

	enbID := createGTPUENB(t, claimENBID(), "net-detach-enb", n3IPv4)

	body := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000020"}`, networkDetachIMSI, testK, testOPc)
	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create UE: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	fullAttach(t, enbID, ueID)

	deleteSubscriber(t, token, networkDetachIMSI)

	status, body2 := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":8000}`)
	if status != 200 {
		t.Fatalf("no Downlink NAS Transport after subscriber deletion (HTTP %d) — the MME must detach the UE (TS 24.301 §5.4.4)\n  body: %s", status, body2)
	}

	if got := jsonGet(body2, "nas.message_type"); got != "detach_request" {
		t.Fatalf("MME-initiated NAS = %q, want detach_request (TS 24.301 §5.4.4)\n  body: %s", got, body2)
	}
}
