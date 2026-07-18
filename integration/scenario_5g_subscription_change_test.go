// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func updateSubscriberProfile(t *testing.T, token, imsi, profile string) {
	t.Helper()

	req, _ := http.NewRequest("PUT", ellaAPIURL+"/api/v1/subscribers/"+imsi,
		strings.NewReader(fmt.Sprintf(`{"profile_name":%q}`, profile)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update subscriber %s -> %s: %v", imsi, profile, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("update subscriber %s -> %s: HTTP %d: %s", imsi, profile, resp.StatusCode, b)
	}
}

// The cause is the SMF's choice on a network-requested release (TS 24.501 §6.3.3).
var validNetworkReleaseCauses = map[string]bool{
	"8": true, "26": true, "29": true, "36": true,
	"38": true, "39": true, "46": true, "67": true, "69": true,
}

func assertValidReleaseCause(t *testing.T, body []byte) {
	t.Helper()

	got := jsonGet(body, "nas.5gsm_cause")
	if got == "" {
		t.Errorf("network-requested release carries no 5GSM cause; the SMF shall set one (TS 24.501 §6.3.3)\n  body: %s", body)
		return
	}

	if !validNetworkReleaseCauses[got] {
		t.Errorf("5GSM cause = %s, want a valid network-requested-release cause (TS 24.501 §6.3.3: 8/26/29/36/38/39/46/67/69)\n  body: %s", got, body)
	}
}

// A profile whose slice (SST 2) does not match the established session orphans it,
// which TS 23.501 §5.15.5.2.2 requires the network to release.
func Test5GSubscriptionChange_SliceRemovedReleasesPDUSession(t *testing.T) {
	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("ella core token: %v", err)
	}

	gnbID := mustCreateGnB(t)
	ueID := mustCreateUEWithSUPI(t, gnbID, subscriptionChangeSUPI)
	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("establish PDU session: HTTP %d\n  body: %s", status, body)
	}

	// Registered before the mutation so the shared subscriber is always restored.
	t.Cleanup(func() { updateSubscriberProfile(t, token, subscriptionChangeIMSI, "default") })

	updateSubscriberProfile(t, token, subscriptionChangeIMSI, "alternate")

	resp := awaitUENGAPWithin(t, gnbID, ueID, 8000, ngapPDUSessionResourceReleaseCommand)
	if got := jsonGet(resp, "ngap.message_type"); got != ngapPDUSessionResourceReleaseCommand {
		t.Fatalf("after slice removed: ngap.message_type = %q, want PDUSessionResourceReleaseCommand (TS 23.501 §5.15.5.2.2)\n  body: %s", got, resp)
	}

	assertValidReleaseCause(t, resp)
}
