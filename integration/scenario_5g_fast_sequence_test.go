// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test5GFastRegisterDeregisterChurn(t *testing.T) {
	gnb := createGNBWithID(t, "00c004", "fast-churn")

	const cycles = 10

	// One subscriber across all cycles: reuse of a single identity is the churn under test.
	supi := claimSubscriber(t)

	for c := 0; c < cycles; c++ {
		r, err := registerSUPI(gnb, supi)
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
