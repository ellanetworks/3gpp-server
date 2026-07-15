// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"sync"
	"sync/atomic"
)

// ENBContext is an emulated eNB's S1-MME association state, including the UE
// contexts attached through it.
type ENBContext struct {
	ID    string
	MCC   string
	MNC   string
	TAC   uint16
	ENBID uint32
	Name  string

	// N3Addr is the eNB's S1-U transport address, advertised as the E-RAB
	// endpoint in the Initial Context Setup Response.
	N3Addr string

	mu          sync.RWMutex
	ues         map[string]*UEEPSContext
	nextENBUEID atomic.Uint32
}

func NewENBContext(id, mcc, mnc string, tac uint16, enbID uint32, name string) *ENBContext {
	return &ENBContext{
		ID:    id,
		MCC:   mcc,
		MNC:   mnc,
		TAC:   tac,
		ENBID: enbID,
		Name:  name,
		ues:   make(map[string]*UEEPSContext),
	}
}

func (e *ENBContext) AllocateENBUES1APID() uint32 {
	return e.nextENBUEID.Add(1)
}

func (e *ENBContext) CreateUE(ue *UEEPSContext) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ues[ue.ID] = ue
}

func (e *ENBContext) GetUE(ueID string) (*UEEPSContext, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ue, ok := e.ues[ueID]

	return ue, ok
}

func (e *ENBContext) DeleteUE(ueID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.deleteUELocked(ueID)
}

func (e *ENBContext) deleteUELocked(ueID string) bool {
	if _, ok := e.ues[ueID]; !ok {
		return false
	}

	delete(e.ues, ueID)

	return true
}

// MigrateUE moves a UE context from this eNB to target, modelling the UE
// arriving at the target after an S1 handover. The context keeps its identity,
// credentials, and EPS NAS security state; non-nil IDs replace its S1AP UE
// identities on the target.
func (e *ENBContext) MigrateUE(target *ENBContext, ue *UEEPSContext, mmeUES1APID, enbUES1APID *uint32) {
	e.mu.Lock()
	e.deleteUELocked(ue.ID)
	e.mu.Unlock()

	if mmeUES1APID != nil {
		ue.MMEUES1APID = *mmeUES1APID
	}

	if enbUES1APID != nil {
		ue.ENBUES1APID = *enbUES1APID
	}

	target.CreateUE(ue)
}
