// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	s1ap "github.com/ellanetworks/core/s1ap"
)

// Test4GCriticalityDiagnostics checks the MME answers an S1AP message whose body
// fails to decode with an ERROR INDICATION carrying the transfer-syntax-error
// Cause (TS 36.413 §10.2). A valid Uplink NAS Transport envelope wrapping a
// malformed body is sent verbatim via the raw-S1AP path so the outer PDU decodes
// but the body parser fails. CriticalityDiagnostics is optional for a
// transfer-syntax error (it is mandated only for abstract-syntax / logical
// errors, §9.2.1.21), so it is asserted only when the MME includes it.
func Test4GCriticalityDiagnostics(t *testing.T) {
	enbID := mustCreateENB(t)

	malformed, err := s1ap.Marshal(&s1ap.InitiatingMessage{
		ProcedureCode: s1ap.ProcUplinkNASTransport,
		Criticality:   s1ap.CriticalityReject,
		Value:         []byte{0xde, 0xad, 0xbe, 0xef},
	})
	if err != nil {
		t.Fatalf("craft malformed S1AP: %v", err)
	}

	body := fmt.Sprintf(`{"raw_s1ap_pdu":%q,"wait_for":["ErrorIndication"],"timeout_ms":5000}`, hex.EncodeToString(malformed))
	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/s1ap", body)
	if status != 200 {
		t.Fatalf("raw s1ap: HTTP %d — the MME must answer a transfer-syntax error with an Error Indication (TS 36.413 §10.2)\n  body: %s", status, resp)
	}

	if got := jsonGet(resp, "s1ap.message_type"); got != "ErrorIndication" {
		t.Fatalf("s1ap.message_type = %q, want ErrorIndication\n  body: %s", got, resp)
	}

	if g, v := jsonGet(resp, "s1ap.cause.group"), jsonGet(resp, "s1ap.cause.value"); g != "protocol" || v != "0" {
		t.Errorf("Error Indication cause = {%s,%s}, want {protocol,0} transfer-syntax-error (TS 36.413 §10.2)\n  body: %s", g, v, resp)
	}

	// CriticalityDiagnostics is optional here; assert its contents only when present.
	if jsonGet(resp, "s1ap.criticality_diagnostics.procedure_code") != "" {
		if got := jsonGet(resp, "s1ap.criticality_diagnostics.procedure_code"); got != "13" {
			t.Errorf("criticality_diagnostics.procedure_code = %q, want 13 (UplinkNASTransport)\n  body: %s", got, resp)
		}

		if got := jsonGet(resp, "s1ap.criticality_diagnostics.triggering_message"); got != "initiating_message" {
			t.Errorf("criticality_diagnostics.triggering_message = %q, want initiating_message\n  body: %s", got, resp)
		}

		if got := jsonGet(resp, "s1ap.criticality_diagnostics.procedure_criticality"); got != "reject" {
			t.Errorf("criticality_diagnostics.procedure_criticality = %q, want reject\n  body: %s", got, resp)
		}
	}
}
