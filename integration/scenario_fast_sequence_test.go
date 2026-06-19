// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Fast sequences: the same UE driving procedures back-to-back with no settle
// time, so a freed resource is reused on the very next step. These catch state
// that lingers or corrupts across rapid reuse rather than across simultaneous
// UEs.

package integration_test

import (
	"testing"
)

// TestFastRegisterDeregisterChurn cycles one subscriber through register →
// deregister repeatedly with no pause. Every cycle must complete: the AMF must
// free the UE's context on each deregistration (TS 24.501 §5.5.2.2) and serve a
// clean registration immediately after, with no hang, leak, or stale state from
// the previous cycle.
func TestFastRegisterDeregisterChurn(t *testing.T) {
	gnb := createGnBWithID(t, "00c004", "fast-churn")

	const cycles = 10

	for c := 0; c < cycles; c++ {
		r, err := registerSUPI(gnb, testSUPI(30))
		if err != nil {
			t.Fatalf("cycle %d: registration failed: %v", c, err)
		}

		if amf := ueAmfNgapID(t, gnb, r.ueID); amf == 0 {
			t.Fatalf("cycle %d: AMF UE NGAP ID not assigned", c)
		}

		if err := deregister(gnb, r.ueID); err != nil {
			t.Fatalf("cycle %d: deregistration failed: %v", c, err)
		}
	}
}
