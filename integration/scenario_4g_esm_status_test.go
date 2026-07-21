// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// The MME renders each PDN connection as a session keyed by its default EPS bearer identity.
func subscriberHasEBI(t *testing.T, token, imsi, ebi string) bool {
	t.Helper()

	req, _ := http.NewRequest("GET", ellaAPIURL+"/api/v1/subscribers/"+imsi, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get subscriber %s: %v", imsi, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read subscriber %s: %v", imsi, err)
	}

	for i := 0; ; i++ {
		id := jsonGet(body, "result.sessions."+strconv.Itoa(i)+".id")
		if id == "" {
			return false
		}

		if id == ebi {
			return true
		}
	}
}

func Test4GESMStatus_InvalidBearerReleases(t *testing.T) {
	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("ella core token: %v", err)
	}

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	ue := getENBUE(t, enbID, ueID)
	imsi, defaultEBI := jsonGet(ue, "imsi"), jsonGet(ue, "default_ebi")

	if !subscriberHasEBI(t, token, imsi, defaultEBI) {
		t.Fatalf("EBI %s absent from subscriber %s before the ESM STATUS; ue: %s", defaultEBI, imsi, ue)
	}

	nasBody(t, enbID, ueID, `{"message_type":"status_esm","esm_cause":43}`)

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["UEContextReleaseCommand"],"timeout_ms":5000}`)
	if status != 200 {
		t.Fatalf("await UEContextReleaseCommand: HTTP %d — the MME must locally deactivate the bearer on ESM STATUS #43 (TS 24.301 §6.7)\n  body: %s", status, body)
	}

	if got := jsonGet(body, "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("s1ap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}

	deadline := time.Now().Add(5 * time.Second)
	for subscriberHasEBI(t, token, imsi, defaultEBI) {
		if time.Now().After(deadline) {
			t.Fatalf("EBI %s still active on subscriber %s 5s after ESM STATUS #43; the MME must deactivate the corresponding EPS bearer context (TS 24.301 §6.7)", defaultEBI, imsi)
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func Test4GESMStatus_SessionRemainsUsable(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	nasBody(t, enbID, ueID, `{"message_type":"status_esm","esm_cause":111}`)

	if s, b := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		`{"message_types":["DownlinkNASTransport"],"timeout_ms":1500}`); s == 200 {
		if got := jsonGet(b, "nas.message_type"); got == "esm_status" {
			t.Fatalf("the MME answered a valid ESM STATUS with an ESM STATUS (must process, not reply, TS 24.301 §6.7)\n  body: %s", b)
		}
	}

	if got := jsonGet(nasStep(t, enbID, ueID, "ue_context_release_request"), "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("UE not usable after sending ESM STATUS; release_request did not yield a UEContextReleaseCommand")
	}
}
