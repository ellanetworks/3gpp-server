// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import "testing"

// TestGnBContextDeleteUEPurgesSideMaps asserts DeleteUE removes the per-UE state
// held in the ranUeID-keyed side-maps, not only the UEs map — otherwise every
// created/deleted UE leaks its NGAP ID, PDU sessions, and AMBR.
func TestGnBContextDeleteUEPurgesSideMaps(t *testing.T) {
	g := NewGnBContext("g1", "001", "01", "000001", "000001", "gnb", 1, "", nil)

	ue := &UEContext{ID: "ue1", RanUeNgapID: 42}
	g.CreateUE(ue)
	g.UpdateNGAPIDs(42, 100)
	g.StorePDUSession(42, &PDUSessionInfo{PDUSessionID: 1})
	g.StoreUEAmbr(42, &UEAmbrInfo{UplinkBps: 1, DownlinkBps: 2})

	if !g.DeleteUE("ue1") {
		t.Fatal("DeleteUE returned false for an existing UE")
	}

	if _, ok := g.GetAMFUENGAPID(42); ok {
		t.Error("NGAPIDs still holds the deleted UE")
	}

	if _, ok := g.GetPDUSession(42, 1); ok {
		t.Error("PDUSessions still holds the deleted UE")
	}

	if len(g.PDUSessions) != 0 {
		t.Errorf("PDUSessions map = %d entries, want 0", len(g.PDUSessions))
	}

	if len(g.NGAPIDs) != 0 {
		t.Errorf("NGAPIDs map = %d entries, want 0", len(g.NGAPIDs))
	}

	if len(g.UEAmbr) != 0 {
		t.Errorf("UEAmbr map = %d entries, want 0", len(g.UEAmbr))
	}
}
