// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

func awaitENBDownlinkNAS(t *testing.T, enbID, ueID string, timeoutMs int) []byte {
	t.Helper()

	return awaitENBUENAS(t, enbID, ueID, timeoutMs, "DownlinkNASTransport")
}

func awaitENBUENAS(t *testing.T, enbID, ueID string, timeoutMs int, messageTypes ...string) []byte {
	t.Helper()

	mt, _ := json.Marshal(messageTypes)

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/await",
		fmt.Sprintf(`{"message_types":%s,"timeout_ms":%d}`, mt, timeoutMs))
	if status != 200 {
		t.Fatalf("await %v (timeout %dms) on ue %s: HTTP %d\n  body: %s", messageTypes, timeoutMs, ueID, status, body)
	}

	return body
}

// TS 24.301 §6.4.3.6 a): on the first expiry of T3486 the MME "shall resend the MODIFY
// EPS BEARER CONTEXT REQUEST". A network-requested session-AMBR change (§6.4.3) drives
// the procedure; withholding the accept lets T3486 expire and forces the retransmission.
func Test4GT3486_ModifyBearerRetransmitted(t *testing.T) {
	skipUnlessTimerTestsEnabled(t)

	token, err := provisionEllaCore()
	if err != nil {
		t.Fatalf("provision Ella Core: %v", err)
	}

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	t.Cleanup(func() { setPolicyAMBR(t, token, "200 Mbps", "200 Mbps") })

	// Baseline then change so the AMBR differs across reruns and a modification is triggered.
	setPolicyAMBR(t, token, "200 Mbps", "200 Mbps")
	setPolicyAMBR(t, token, "50 Mbps", "50 Mbps")

	first := awaitENBDownlinkNAS(t, enbID, ueID, procedureTimerWaitMs)
	if got := jsonGet(first, "nas.message_type"); got != "modify_eps_bearer_context_request" {
		t.Fatalf("initial: nas.message_type = %q, want modify_eps_bearer_context_request (TS 24.301 §6.4.3)\n  body: %s", got, first)
	}

	// The command and its T3486 retransmissions are indistinguishable, so the first await
	// consumes whichever arrived and the second proves a retransmission.
	second := awaitENBDownlinkNAS(t, enbID, ueID, procedureTimerWaitMs)
	if got := jsonGet(second, "nas.message_type"); got != "modify_eps_bearer_context_request" {
		t.Errorf("retransmission: nas.message_type = %q, want modify_eps_bearer_context_request (TS 24.301 §6.4.3.6 a))\n  body: %s", got, second)
	}

	// Unasserted: stops T3486 so the bearer commits the modification.
	accept := fmt.Sprintf(`{"message_type":"modify_eps_bearer_context_accept","eps_bearer_identity":%s,"pti":%s}`,
		jsonGet(first, "nas.eps_bearer_identity"), jsonGet(first, "nas.bearer_pti"))
	doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap", accept)
}

// TS 24.301 §6.4.1.6 a): on the first expiry of T3485 the MME "shall resend the ACTIVATE
// DEFAULT EPS BEARER CONTEXT REQUEST". Only a stand-alone PDN connectivity starts T3485;
// §6.4.1.2 says the MME "shall not start the timer T3485" when the default bearer is
// activated as part of the attach. Withholding the accept lets T3485 expire.
func Test4GT3485_ActivateBearerRetransmitted(t *testing.T) {
	skipUnlessTimerTestsEnabled(t)

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	first := nasBody(t, enbID, ueID, `{"message_type":"pdn_connectivity","apn":"internet46","withhold_accept":true,"timeout_ms":6000}`)
	if got := jsonGet(first, "nas.message_type"); got != "activate_default_eps_bearer_context_request" {
		t.Fatalf("initial: nas.message_type = %q, want activate_default_eps_bearer_context_request (TS 24.301 §6.4.1.2)\n  body: %s", got, first)
	}

	// The command and its T3485 retransmissions are indistinguishable, so the second await proves a retransmission.
	second := awaitENBUENAS(t, enbID, ueID, procedureTimerWaitMs, "ERABSetupRequest", "DownlinkNASTransport")
	if got := jsonGet(second, "nas.message_type"); got != "activate_default_eps_bearer_context_request" {
		t.Errorf("retransmission: nas.message_type = %q, want activate_default_eps_bearer_context_request (TS 24.301 §6.4.1.6 a))\n  body: %s", got, second)
	}
}

// TS 24.301 §6.4.4.5 a): on the first expiry of T3495 the MME "shall resend the DEACTIVATE
// EPS BEARER CONTEXT REQUEST". A PDN disconnect drives the deactivation; withholding the
// accept lets T3495 expire.
func Test4GT3495_DeactivateBearerRetransmitted(t *testing.T) {
	skipUnlessTimerTestsEnabled(t)

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	ebi := connectSecondPDN(t, enbID, ueID)

	first := nasBody(t, enbID, ueID, `{"message_type":"pdn_disconnect","linked_ebi":`+ebi+`,"withhold_accept":true,"timeout_ms":6000}`)
	if got := jsonGet(first, "nas.message_type"); got != "deactivate_eps_bearer_context_request" {
		t.Fatalf("initial: nas.message_type = %q, want deactivate_eps_bearer_context_request (TS 24.301 §6.4.4.2)\n  body: %s", got, first)
	}

	second := awaitENBUENAS(t, enbID, ueID, procedureTimerWaitMs, "ERABReleaseCommand", "DownlinkNASTransport")
	if got := jsonGet(second, "nas.message_type"); got != "deactivate_eps_bearer_context_request" {
		t.Errorf("retransmission: nas.message_type = %q, want deactivate_eps_bearer_context_request (TS 24.301 §6.4.4.5 a))\n  body: %s", got, second)
	}
}
