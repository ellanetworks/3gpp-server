//go:build integration

// Network-requested-procedure retransmission timers (TS 24.501):
//   - T3592 (§6.3.3, abnormal case a): the SMF retransmits the PDU Session
//     Release Command on each expiry until the UE confirms with a Release
//     Complete.
//   - T3591 (§6.3.2.5): the SMF retransmits the PDU Session Modification Command
//     on each expiry until the UE confirms with a Modification Complete.
//
// Both timers are 16 s (TS 24.501 table 10.3.2). Observing a single
// retransmission proves the timer fires and resends; the abort-on-fifth-expiry
// behaviour is covered by Ella Core's SMF unit tests. Each test waits more than
// 16 s, so the suite is skipped unless ELLA_RUN_TIMER_RETRANSMISSION_TESTS is set.

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

// procedureTimerWaitMs exceeds the 16 s T3591/T3592 interval with margin.
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

// awaitUENGAPWithin waits up to timeoutMs for an unsolicited downlink NGAP
// message of one of messageTypes addressed to the UE.
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

// TestT3592_ReleaseCommandRetransmitted drives a network-requested release and,
// by withholding the Release Complete, observes the SMF retransmit the Release
// Command when T3592 expires (TS 24.501 §6.3.3, abnormal case a).
func TestT3592_ReleaseCommandRetransmitted(t *testing.T) {
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

	// The UE acknowledges neither the N1 Release Complete nor the N2 release
	// response, so T3592 expires and the SMF resends the command.
	resp := awaitUENGAPWithin(t, gnbID, ueID, procedureTimerWaitMs, ngapPDUSessionResourceReleaseCommand)
	if got := jsonGet(resp, "nas.inner_nas_message_type"); got != nasPDUSessionReleaseCommand {
		t.Errorf("retransmission: nas.inner_nas_message_type = %q, want pdu_session_release_command\n  body: %s", got, resp)
	}

	// Confirm the release so T3592 stops and the session is torn down.
	doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_release_complete"}`)
}

// TestT3591_ModificationCommandRetransmitted changes a session's AMBR so the
// session reconciler issues a network-requested PDU Session Modification, then,
// by withholding the Modification Complete, observes the SMF retransmit the
// Modification Command when T3591 expires (TS 24.501 §6.3.2.5).
func TestT3591_ModificationCommandRetransmitted(t *testing.T) {
	skipUnlessTimerTestsEnabled(t)

	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("provision Ella Core: %v", err)
	}

	// A dedicated data network, policy and subscriber so the AMBR can be mutated
	// without disturbing other tests.
	mustEllaProvision(t, token, "/api/v1/networking/data-networks", modTimerDNN,
		fmt.Sprintf(`{"name":%q,"ipv4_pool":"10.77.0.0/24","dns":"8.8.8.8","mtu":1400}`, modTimerDNN))
	mustEllaProvision(t, token, "/api/v1/policies", modTimerPolicy, modTimerPolicyBody("200 Mbps"))

	// Baseline the AMBR so the later change is a guaranteed difference even when
	// the test environment persists across runs.
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

	// Changing the AMBR wakes the session reconciler, which drives a
	// network-requested PDU Session Modification (TS 24.501 §6.3.2).
	mustEllaUpdatePolicy(t, token, "300 Mbps")

	// The Modification Command and its T3591 retransmissions are all
	// PDUSessionResourceModifyRequests. Consume the first one observed (the
	// initial command or, if it arrived before this waiter registered, an early
	// retransmission), then require a further one: a second command for the same
	// procedure is a retransmission, since the UE never sends a Modification
	// Complete (TS 24.501 §6.3.2.5).
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
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("update policy %s: HTTP %d: %s", modTimerPolicy, resp.StatusCode, b)
	}
}
