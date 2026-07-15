// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import "testing"

// TestENBContextMigrateUE asserts the UE leaves the source, arrives at the
// target, and takes the given S1AP UE identities.
func TestENBContextMigrateUE(t *testing.T) {
	src := NewENBContext("e1", "001", "01", 1, 1, "src")
	target := NewENBContext("e2", "001", "01", 1, 2, "target")

	ue := NewUEEPSContext("1", 1, &CreateUEEPSOpts{IMSI: "001010000000001"})
	src.CreateUE(ue)

	newMME, newENB := uint32(500), uint32(100)
	src.MigrateUE(target, ue, &newMME, &newENB)

	if _, ok := src.GetUE("1"); ok {
		t.Error("source still holds the migrated UE")
	}

	got, ok := target.GetUE("1")
	if !ok {
		t.Fatal("target does not hold the migrated UE")
	}

	if got.MMEUES1APID != newMME {
		t.Errorf("MMEUES1APID = %d, want %d", got.MMEUES1APID, newMME)
	}

	if got.ENBUES1APID != newENB {
		t.Errorf("ENBUES1APID = %d, want %d", got.ENBUES1APID, newENB)
	}
}

// TestENBContextAllocateENBUES1APID asserts the eNB UE S1AP ID is monotonic, so
// no two UE associations on an eNB share an identity.
func TestENBContextAllocateENBUES1APID(t *testing.T) {
	e := NewENBContext("e1", "001", "01", 1, 1, "enb")

	for want := uint32(1); want <= 3; want++ {
		if got := e.AllocateENBUES1APID(); got != want {
			t.Errorf("AllocateENBUES1APID() = %d, want %d", got, want)
		}
	}
}
