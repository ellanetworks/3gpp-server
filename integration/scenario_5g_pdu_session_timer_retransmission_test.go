// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// procedureTimerWaitMs exceeds the T3591/T3592 retransmission interval with margin.
const procedureTimerWaitMs = 22000

const (
	modTimerDNN    = "modtimer"
	modTimerPolicy = "modtimer-policy"
)

func skipUnlessTimerTestsEnabled(t *testing.T) {
	t.Helper()

	if os.Getenv("ELLA_RUN_TIMER_RETRANSMISSION_TESTS") == "" {
		t.Skip("slow (>16 s) retransmission-timer test; set ELLA_RUN_TIMER_RETRANSMISSION_TESTS=1 to run")
	}
}

func awaitUENGAPWithin(t *testing.T, gnbID, ueID string, timeoutMs int, messageTypes ...string) []byte {
	t.Helper()

	mt, _ := json.Marshal(messageTypes)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/await",
		fmt.Sprintf(`{"message_types": %s, "timeout_ms": %d}`, mt, timeoutMs))
	if status != 200 {
		t.Fatalf("await %v (timeout %dms) on ue %s: HTTP %d\n  body: %s", messageTypes, timeoutMs, ueID, status, body)
	}

	return body
}

func Test5GT3592_ReleaseCommandRetransmitted(t *testing.T) {
	skipUnlessTimerTestsEnabled(t)

	gnbID, ueID := establishedPDUSession(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_request"}`)
	if status != 200 {
		t.Fatalf("release request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapPDUSessionResourceReleaseCommand {
		t.Fatalf("initial: ngap.message_type = %q, want PDUSessionResourceReleaseCommand\n  body: %s", got, body)
	}

	// Withholding both the N1 and N2 responses is what expires T3592 (TS 24.501 §6.3.3.5 a).
	resp := awaitUENGAPWithin(t, gnbID, ueID, procedureTimerWaitMs, ngapPDUSessionResourceReleaseCommand)
	if got := jsonGet(resp, "nas.inner_nas_message_type"); got != nasPDUSessionReleaseCommand {
		t.Errorf("retransmission: nas.inner_nas_message_type = %q, want pdu_session_release_command\n  body: %s", got, resp)
	}

	// Unasserted: stops T3592 so the session tears down.
	doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_complete"}`)
}

func Test5GT3591_ModificationCommandRetransmitted(t *testing.T) {
	skipUnlessTimerTestsEnabled(t)

	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("provision Ella Core: %v", err)
	}

	// A dedicated data network and policy so the AMBR can be mutated in isolation.
	mustEllaProvision(t, token, "/api/v1/networking/data-networks", modTimerDNN,
		fmt.Sprintf(`{"name":%q,"ipv4_pool":"10.77.0.0/24","dns":"8.8.8.8","mtu":1400}`, modTimerDNN))
	mustEllaProvision(t, token, "/api/v1/policies", modTimerPolicy, modTimerPolicyBody("200 Mbps"))

	// Unasserted: baselines the AMBR so the later change differs across reruns.
	mustEllaUpdatePolicy(t, token, "200 Mbps")

	gnbID := mustCreateGnB(t)
	ueID := mustCreateUEWithDNN(t, gnbID, modTimerDNN)

	doRegistrationFlow(t, gnbID, ueID)
	t.Cleanup(func() {
		doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"deregistration_request"}`)
	})

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 || jsonGet(body, "nas.inner_nas_message_type") != nasPDUSessionEstablishmentAccept {
		t.Fatalf("establish on %s: HTTP %d\n  body: %s", modTimerDNN, status, body)
	}

	// An AMBR change drives a network-requested PDU Session Modification (TS 24.501 §6.3.2).
	mustEllaUpdatePolicy(t, token, "300 Mbps")

	// The command and its T3591 retransmissions are indistinguishable, so the first
	// await consumes whichever arrived and the second proves a retransmission.
	awaitUENGAPWithin(t, gnbID, ueID, procedureTimerWaitMs, ngapPDUSessionResourceModifyRequest)
	awaitUENGAPWithin(t, gnbID, ueID, procedureTimerWaitMs, ngapPDUSessionResourceModifyRequest)
}

func modTimerPolicyBody(ambr string) string {
	return fmt.Sprintf(`{"name":%q,"profile_name":"default","slice_name":"default","data_network_name":%q,"session_ambr_uplink":%q,"session_ambr_downlink":%q,"var5qi":9,"arp":1}`,
		modTimerPolicy, modTimerDNN, ambr, ambr)
}

func mustEllaProvision(t *testing.T, token, collectionPath, name, body string) {
	t.Helper()

	if err := ensureProvisioned(token, collectionPath, name, body); err != nil {
		t.Fatalf("provision %s/%s: %v", collectionPath, name, err)
	}
}

func mustEllaUpdatePolicy(t *testing.T, token, ambr string) {
	t.Helper()

	req, _ := http.NewRequest("PUT", ellaAPIURL+"/api/v1/policies/"+modTimerPolicy, strings.NewReader(modTimerPolicyBody(ambr)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("update policy %s: HTTP %d: %s", modTimerPolicy, resp.StatusCode, b)
	}
}
