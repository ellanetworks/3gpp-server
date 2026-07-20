// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// 00 initiating message, 2e procedure code 46 (UplinkNASTransport), 40 criticality
// "ignore", 04 open-type length over a garbage body (TS 38.413 §9.4.3).
const ngapTransferSyntaxErrorPDU = "002e4004deadbeef"

func Test5GCriticalityDiagnostics(t *testing.T) {
	gnbID := mustCreateGNB(t)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap",
		`{"raw_ngap_pdu":"`+ngapTransferSyntaxErrorPDU+`","wait_for":["ErrorIndication"],"timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("raw ngap: HTTP %d, want 200 — a transfer-syntax error must draw an Error Indication (TS 38.413 §10.2)\n  body: %s", status, resp)
	}

	assertTransferSyntaxErrorIndication(t, resp)

	mustCreateGNB(t)
}

func assertTransferSyntaxErrorIndication(t *testing.T, body []byte) {
	t.Helper()

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Fatalf("ngap.message_type = %q, want ErrorIndication (TS 38.413 §10.2)\n  body: %s", got, body)
	}

	hasCause := ngapHasCause(body)
	cd := ngapCriticalityDiagnostics(body)

	if !hasCause && cd == nil {
		t.Fatalf("ErrorIndication carries neither a Cause IE nor a Criticality Diagnostics IE; at least one is required (TS 38.413 §8.7.5.2)\n  body: %s", body)
	}

	if hasCause {
		if group, val := ngapCause(body, "ngap"); group != "protocol" || val != causeProtocolTransferSyntaxError {
			t.Errorf("ErrorIndication cause = (%q, %d), want (\"protocol\", %d) transfer-syntax-error (TS 38.413 §10.2)\n  body: %s",
				group, val, causeProtocolTransferSyntaxError, body)
		}
	}

	// TS 38.413 §9.3.1.3 mandates Criticality Diagnostics only for not-comprehended,
	// missing or logically erroneous IEs, so a transfer-syntax error may omit it.
	if cd == nil {
		return
	}

	if cd.ProcedureCode != nil && *cd.ProcedureCode != ngapProcedureCodeUplinkNASTransport {
		t.Errorf("criticality_diagnostics.procedure_code = %d, want %d (UplinkNASTransport)\n  body: %s",
			*cd.ProcedureCode, ngapProcedureCodeUplinkNASTransport, body)
	}

	if cd.TriggeringMessage != nil && *cd.TriggeringMessage != "initiating_message" {
		t.Errorf("criticality_diagnostics.triggering_message = %q, want initiating_message\n  body: %s", *cd.TriggeringMessage, body)
	}

	if cd.ProcedureCriticality != nil && *cd.ProcedureCriticality != "ignore" {
		t.Errorf("criticality_diagnostics.procedure_criticality = %q, want ignore — the criticality signalled for UplinkNASTransport (TS 38.413 §9.4.3)\n  body: %s",
			*cd.ProcedureCriticality, body)
	}
}
