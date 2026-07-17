// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func createENBUEForIMSI(t *testing.T, enbID, imsi string) string {
	t.Helper()

	body := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000000"}`, imsi, testK, testOPc)

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create ue: HTTP %d: %s", status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	if ueID == "" {
		t.Fatalf("create ue: no ue_id: %s", resp)
	}

	return ueID
}

func Test4GFastAttachDetachChurn(t *testing.T) {
	enbID := mustCreateENB(t)

	const cycles = 10

	// One subscriber across all cycles: reuse of a single identity is the churn under test.
	imsi := claimSubscriber(t)[len("imsi-"):]

	for c := 0; c < cycles; c++ {
		ueID := createENBUEForIMSI(t, enbID, imsi)

		fullAttach(t, enbID, ueID)

		resp := nasStep(t, enbID, ueID, "detach_request")
		if got := jsonGet(resp, "nas.message_type"); got != "detach_accept" {
			t.Fatalf("cycle %d: detach nas.message_type = %q, want detach_accept (TS 24.301 §5.5.2.2.2); body: %s", c, got, resp)
		}
	}
}
