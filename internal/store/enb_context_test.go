// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import "testing"

func TestENBContextMigrateUE(t *testing.T) {
	src := NewENBContext("e1", "001", "01", "0001", "1", 20, "src")
	target := NewENBContext("e2", "001", "01", "0001", "2", 20, "target")

	ue := NewUEEPSContext("1", 1, &CreateUEEPSOpts{IMSI: "001010000000001"})
	ue.Bearers[5] = &EPSBearer{EBI: 5}
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

	if _, ok := got.Bearers[5]; !ok {
		t.Error("migrated UE lost its EPS bearer")
	}
}

func TestENBContextAllocateENBUES1APID(t *testing.T) {
	e := NewENBContext("e1", "001", "01", "0001", "1", 20, "enb")

	for want := uint32(1); want <= 3; want++ {
		if got := e.AllocateENBUES1APID(); got != want {
			t.Errorf("AllocateENBUES1APID() = %d, want %d", got, want)
		}
	}
}
