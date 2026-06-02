//go:build integration

package integration_test

import (
	"encoding/json"
	"testing"
)

// ngapErrorIndicationIDs returns the AMF and RAN UE NGAP IDs carried in the
// response's IE list (nil when absent).
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

// assertSpecCompliantErrorIndication checks that a response to a UE-associated
// message carrying a wrong AMF/RAN UE NGAP ID is an Error Indication with the
// IEs TS 38.413 §10.6 and §8.7.5.2 require: it uses UE-associated signalling
// (both UE NGAP IDs echoed) and carries a Cause. The exact §10.6 cause
// (Unknown local / Inconsistent remote UE NGAP ID) is pinned in the core3 unit
// tests for resolveUE.
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
