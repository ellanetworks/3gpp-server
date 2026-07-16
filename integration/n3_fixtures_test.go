// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

type n3Transport struct {
	name  string
	ranN3 string
	upfN3 string
}

var (
	n3IPv4 = n3Transport{name: "n3v4", ranN3: "10.3.0.3", upfN3: "10.3.0.2"}
	n3IPv6 = n3Transport{name: "n3v6", ranN3: "fd00:3::3", upfN3: "fd00:3::2"}
)

const dnResponderIP = "10.6.0.10"

const udpEchoPort = 7

// badTEID is a non-zero TEID with no PDR at the UPF.
const badTEID = 0xFFFFFFFE

// TS 29.281 §5.1, §7.3.1 and Table 7.3.1-1. wantPeer is the destination address of the triggering G-PDU.
func assertGTPUErrorIndication(t *testing.T, body []byte, wantPeer string) {
	t.Helper()

	if got := jsonGet(body, "header_teid"); got != "0" {
		t.Errorf("Error Indication header TEID = %q, want 0 (TS 29.281 §5.1)\n  body: %s", got, body)
	}

	want := fmt.Sprintf("%d", uint32(badTEID))
	if got := jsonGet(body, "teid_data_i"); got != want {
		t.Errorf("Error Indication TEID Data I = %q, want %q — it shall be the TEID fetched from the triggering G-PDU (TS 29.281 §7.3.1)\n  body: %s", got, want, body)
	}

	if got := jsonGet(body, "gtpu_peer_address"); got != wantPeer {
		t.Errorf("Error Indication GTP-U Peer Address = %q, want %q — it shall be the destination address of the triggering G-PDU (TS 29.281 §7.3.1)\n  body: %s", got, wantPeer, body)
	}
}

// TS 29.281 §7.2.2 and Table 7.2.2-1.
func assertEchoResponseRecovery(t *testing.T, body []byte) {
	t.Helper()

	if got := jsonGet(body, "recovery_restart_counter"); got != "0" {
		t.Errorf("Echo Response Recovery restart counter = %q, want 0 — Recovery is mandatory and its Restart Counter shall be set to zero by the sender (TS 29.281 §7.2.2)\n  body: %s", got, body)
	}
}

// TS 38.415 §5.5.2.1: the QFI is a fixed octet of the DL frame and the RQI field shall be included.
func assertDLPDUSessionInformation(t *testing.T, body []byte) {
	t.Helper()

	if got := jsonGet(body, "pdu_session_container.pdu_type"); got != "0" {
		t.Errorf("downlink N3 PDU Session Container PDU Type = %q, want 0 (DL PDU SESSION INFORMATION) (TS 38.415 §5.5.2.1)\n  body: %s", got, body)
		return
	}

	if got := jsonGet(body, "pdu_session_container.qfi"); got == "" {
		t.Errorf("downlink DL PDU SESSION INFORMATION carries no QoS Flow Identifier field (TS 38.415 §5.5.2.1)\n  body: %s", body)
	}

	if got := jsonGet(body, "pdu_session_container.rqi"); got != "true" && got != "false" {
		t.Errorf("downlink DL PDU SESSION INFORMATION Reflective QoS Indicator field = %q, want true or false (TS 38.415 §5.5.2.1)\n  body: %s", got, body)
	}
}
