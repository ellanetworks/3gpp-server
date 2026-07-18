// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import "testing"

func TestGNBContextMigrateUE(t *testing.T) {
	src := NewGNBContext("g1", "001", "01", "000001", "000001", "src", 1, "", nil)
	target := NewGNBContext("g2", "001", "01", "000001", "000002", "target", 1, "", nil)

	ue := &UEContext{ID: "ue1", RANUENGAPID: 42, PDUSessions: map[uint8]*PDUSessionInfo{1: {PDUSessionID: 1}}}
	src.CreateUE(ue)

	newRan, newAmf := int64(7), int64(99)
	src.MigrateUE(target, ue, &newRan, &newAmf)

	if _, ok := src.GetUE("ue1"); ok {
		t.Error("source still holds the migrated UE")
	}

	got, ok := target.GetUE("ue1")
	if !ok {
		t.Fatal("target does not hold the migrated UE")
	}

	if got.RANUENGAPID != newRan {
		t.Errorf("RANUENGAPID = %d, want %d", got.RANUENGAPID, newRan)
	}

	if got.AMFUENGAPID != newAmf {
		t.Errorf("AMFUENGAPID = %d, want %d", got.AMFUENGAPID, newAmf)
	}

	if _, ok := got.PDUSessions[1]; !ok {
		t.Error("migrated UE lost its PDU session")
	}
}

func TestGNBContextAllocateRanUeNgapID(t *testing.T) {
	g := NewGNBContext("g1", "001", "01", "000001", "000001", "gnb", 1, "", nil)

	for want := int64(1); want <= 3; want++ {
		if got := g.AllocateRANUENGAPID(); got != want {
			t.Errorf("AllocateRANUENGAPID() = %d, want %d", got, want)
		}
	}
}
