// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"net/http"
	"testing"
)

// networkDetachIMSI is a dedicated subscriber the network-detach test deletes to
// trigger the procedure, so it never disturbs the shared subscriber pool.
const networkDetachIMSI = "001010000000102"

// deleteSubscriber removes a subscriber via the Ella Core admin API.
func deleteSubscriber(t *testing.T, token, imsi string) {
	t.Helper()

	req, _ := http.NewRequest("DELETE", ellaAPIURL+"/api/v1/subscribers/"+imsi, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete subscriber %s: %v", imsi, err)
	}

	resp.Body.Close()
}

// Test4GNetworkInitiatedDetach: deleting an attached subscriber must make the MME
// detach it from the network. The MME sends a network-initiated DETACH REQUEST
// (TS 24.301 §5.4.4) over a Downlink NAS Transport and tears the UE's S1 context
// down with a UE Context Release Command (TS 36.413 §8.3). The emulated eNB
// observes them on its UE-associated await.
func Test4GNetworkInitiatedDetach(t *testing.T) {
	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("ella core token: %v", err)
	}

	if err := createSubscriber(token, networkDetachIMSI); err != nil {
		t.Fatalf("create subscriber: %v", err)
	}
	// Recreate the deleted subscriber so the env is left as found for re-runs.
	t.Cleanup(func() { createSubscriber(token, networkDetachIMSI) })

	enbID := createGTPUENB(t, 1, "net-detach-enb")

	body := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000020"}`, networkDetachIMSI, testK, testOPc)
	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create UE: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	fullAttach(t, enbID, ueID)

	// Trigger: removing the subscriber must detach it.
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
