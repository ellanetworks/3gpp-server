// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// An Uplink NAS Transport (procedure code 46 = 0x2e, criticality "ignore" =
// 0x40 — TS 38.413 §9.4.3) carrying a legal 4-octet open-type length
// determinant over a body of garbage: the outer PDU is well formed while its
// contents cannot be decoded, the "receiver is not able to decode the received
// physical message" case of TS 38.413 §10.2. Test4GCriticalityDiagnostics
// builds the same class of error on S1AP, feeding both RATs one stimulus.
const ngapTransferSyntaxErrorPDU = "002e4004deadbeef"

// TS 38.413 §10.2: on a body that fails to decode the receiver "should initiate
// Error Indication procedure with appropriate cause value for the Transfer
// Syntax protocol error". The Error Indication must carry the §10.2 cause and
// satisfy §8.7.5.2 ("The ERROR INDICATION message shall contain at least either
// the Cause IE or the Criticality Diagnostics IE"), and the AMF must survive.
func Test5GCriticalityDiagnostics(t *testing.T) {
	gnbID := mustCreateGnB(t)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap",
		`{"raw_ngap_pdu":"`+ngapTransferSyntaxErrorPDU+`","wait_for":["ErrorIndication"],"timeout_ms":3000}`)
	if status != 200 {
		t.Fatalf("raw ngap: HTTP %d, want 200 — a transfer-syntax error must draw an Error Indication (TS 38.413 §10.2)\n  body: %s", status, resp)
	}

	assertTransferSyntaxErrorIndication(t, resp)

	// A fresh gNB completing NG Setup proves the AMF survived the stimulus.
	mustCreateGnB(t)
}

// assertTransferSyntaxErrorIndication checks the IEs TS 38.413 §8.7.5.2
// requires and the cause §10.2 names.
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

	// Criticality Diagnostics is optional for a transfer syntax error (TS 38.413
	// §9.3.1.3 mandates it only for not-comprehended, missing or logically
	// erroneous IEs), so its contents are asserted only when the AMF includes it.
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
