// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"sync"
	"sync/atomic"
)

type GNBContext struct {
	ID    string
	MCC   string
	MNC   string
	SST   int32
	SD    string
	TAC   string
	GNBID string
	Name  string

	N3Addr string

	Slices []SliceConfig

	mu          sync.RWMutex
	ues         map[string]*UEContext
	nextRanUeID atomic.Int64
}

type SliceConfig struct {
	SST int32
	SD  string
}

func NewGNBContext(id, mcc, mnc, tac, gnbID, name string, sst int32, sd string, slices []SliceConfig) *GNBContext {
	return &GNBContext{
		ID:     id,
		MCC:    mcc,
		MNC:    mnc,
		SST:    sst,
		SD:     sd,
		TAC:    tac,
		GNBID:  gnbID,
		Name:   name,
		Slices: slices,
		ues:    make(map[string]*UEContext),
	}
}

func (g *GNBContext) AllocateRANUENGAPID() int64 {
	return g.nextRanUeID.Add(1)
}

func (g *GNBContext) CreateUE(ue *UEContext) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ues[ue.ID] = ue
}

func (g *GNBContext) GetUE(ueID string) (*UEContext, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ue, ok := g.ues[ueID]

	return ue, ok
}

func (g *GNBContext) DeleteUE(ueID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.deleteUELocked(ueID)
}

func (g *GNBContext) deleteUELocked(ueID string) bool {
	if _, ok := g.ues[ueID]; !ok {
		return false
	}

	delete(g.ues, ueID)

	return true
}

func (g *GNBContext) MigrateUE(target *GNBContext, ue *UEContext, ranUeNgapID, amfUeNgapID *int64) {
	g.mu.Lock()
	g.deleteUELocked(ue.ID)
	g.mu.Unlock()

	if ranUeNgapID != nil {
		ue.RANUENGAPID = *ranUeNgapID
	}

	if amfUeNgapID != nil {
		ue.AMFUENGAPID = *amfUeNgapID
	}

	target.CreateUE(ue)
}
