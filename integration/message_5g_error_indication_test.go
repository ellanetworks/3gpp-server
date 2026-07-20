// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"testing"
)

func ngapErrorIndicationIDs(body []byte) (amf, ran *int64) {
	var top struct {
		NGAP struct {
			AMFUENGAPID *int64 `json:"amf_ue_ngap_id"`
			RANUENGAPID *int64 `json:"ran_ue_ngap_id"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil, nil
	}

	return top.NGAP.AMFUENGAPID, top.NGAP.RANUENGAPID
}

type criticalityDiagnosticsJSON struct {
	ProcedureCode        *int64  `json:"procedure_code"`
	TriggeringMessage    *string `json:"triggering_message"`
	ProcedureCriticality *string `json:"procedure_criticality"`
}

func ngapCriticalityDiagnostics(body []byte) *criticalityDiagnosticsJSON {
	var top struct {
		NGAP struct {
			CriticalityDiagnostics *criticalityDiagnosticsJSON `json:"criticality_diagnostics"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	return top.NGAP.CriticalityDiagnostics
}

// Which of the two TS 38.413 §10.6 causes applies depends on the mutated ID, so
// only the presence of a Cause is asserted.
func assertSpecCompliantErrorIndication(t *testing.T, body []byte) {
	t.Helper()

	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("ngap.message_type = %q, want ErrorIndication (TS 38.413 §10.6)\n  body: %s", got, body)
		return
	}

	if !ngapHasCause(body) {
		t.Errorf("ErrorIndication missing mandatory Cause IE (TS 38.413 §8.7.5.2)\n  body: %s", body)
	}

	if amf, ran := ngapErrorIndicationIDs(body); amf == nil || ran == nil {
		t.Errorf("ErrorIndication must echo both AMF and RAN UE NGAP IDs for UE-associated signalling (TS 38.413 §8.7.5.2)\n  body: %s", body)
	}
}
