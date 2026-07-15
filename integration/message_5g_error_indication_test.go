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
			IEs []struct {
				AmfUeNgapID *int64 `json:"amf_ue_ngap_id"`
				RanUeNgapID *int64 `json:"ran_ue_ngap_id"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil, nil
	}

	for _, ie := range top.NGAP.IEs {
		if ie.AmfUeNgapID != nil {
			amf = ie.AmfUeNgapID
		}

		if ie.RanUeNgapID != nil {
			ran = ie.RanUeNgapID
		}
	}

	return amf, ran
}

// criticalityDiagnosticsJSON mirrors the Criticality Diagnostics IE the server
// decodes (TS 38.413 §9.3.1.3); every field is optional there.
type criticalityDiagnosticsJSON struct {
	ProcedureCode        *int64  `json:"procedure_code"`
	TriggeringMessage    *string `json:"triggering_message"`
	ProcedureCriticality *string `json:"procedure_criticality"`
}

func ngapCriticalityDiagnostics(body []byte) *criticalityDiagnosticsJSON {
	var top struct {
		NGAP struct {
			IEs []struct {
				CriticalityDiagnostics *criticalityDiagnosticsJSON `json:"criticality_diagnostics"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	for _, ie := range top.NGAP.IEs {
		if ie.CriticalityDiagnostics != nil {
			return ie.CriticalityDiagnostics
		}
	}

	return nil
}

// assertSpecCompliantErrorIndication checks the IEs TS 38.413 §10.6 and
// §8.7.5.2 require of an Error Indication answering a UE-associated message
// with a wrong AMF/RAN UE NGAP ID: UE-associated signalling (both UE NGAP IDs
// echoed) and a Cause. Which of the two §10.6 causes applies (Unknown local or
// Inconsistent remote UE NGAP ID) depends on the mutated ID, so only the
// presence of a Cause is asserted.
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
