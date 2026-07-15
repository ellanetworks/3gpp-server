// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import "testing"

// TestGNBContextDeleteUEPurgesSessions asserts DeleteUE removes the per-UE state
// held in the ranUeID-keyed session map, not only the UE map — otherwise every
// created/deleted UE leaks its PDU sessions.
func TestGNBContextDeleteUEPurgesSessions(t *testing.T) {
	g := NewGNBContext("g1", "001", "01", "000001", "000001", "gnb", 1, "", nil)

	ue := &UEContext{ID: "ue1", RanUeNgapID: 42}
	g.CreateUE(ue)
	g.StorePDUSession(42, &PDUSessionInfo{PDUSessionID: 1})

	if !g.DeleteUE("ue1") {
		t.Fatal("DeleteUE returned false for an existing UE")
	}

	if _, ok := g.GetPDUSession(42, 1); ok {
		t.Error("the session map still holds the deleted UE")
	}

	if len(g.pduSessions) != 0 {
		t.Errorf("session map = %d entries, want 0", len(g.pduSessions))
	}
}

// TestGNBContextMigrateUEPurgesSourceUnderOldID asserts MigrateUE purges the
// source's session state keyed by the UE's pre-migration RAN-UE-NGAP-ID: a rekey
// applied before the purge orphans the source's entry.
func TestGNBContextMigrateUEPurgesSourceUnderOldID(t *testing.T) {
	src := NewGNBContext("g1", "001", "01", "000001", "000001", "src", 1, "", nil)
	target := NewGNBContext("g2", "001", "01", "000001", "000002", "target", 1, "", nil)

	ue := &UEContext{ID: "ue1", RanUeNgapID: 42}
	src.CreateUE(ue)
	src.StorePDUSession(42, &PDUSessionInfo{PDUSessionID: 1})

	newRan, newAmf := int64(7), int64(99)
	src.MigrateUE(target, ue, &newRan, &newAmf)

	if len(src.pduSessions) != 0 {
		t.Errorf("source session map = %d entries, want 0", len(src.pduSessions))
	}

	if _, ok := src.GetUE("ue1"); ok {
		t.Error("source still holds the migrated UE")
	}

	got, ok := target.GetUE("ue1")
	if !ok {
		t.Fatal("target does not hold the migrated UE")
	}

	if got.RanUeNgapID != newRan {
		t.Errorf("RanUeNgapID = %d, want %d", got.RanUeNgapID, newRan)
	}

	if got.AmfUeNgapID != newAmf {
		t.Errorf("AmfUeNgapID = %d, want %d", got.AmfUeNgapID, newAmf)
	}
}
