// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"strconv"
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

	mu         sync.RWMutex
	ues        map[string]*UEEPSContext
	nextUEID   atomic.Int64
	nextENBUES atomic.Int64
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

// CreateUE allocates a UE context with a fresh eNB UE S1AP ID and store handle.
func (e *ENBContext) CreateUE(imsi, k, opc, amf, sqn string) *UEEPSContext {
	ue := &UEEPSContext{
		ID:          strconv.FormatInt(e.nextUEID.Add(1), 10),
		IMSI:        imsi,
		K:           k,
		OPc:         opc,
		AMF:         amf,
		SQN:         sqn,
		ENBUES1APID: uint32(e.nextENBUES.Add(1)),
		Bearers:     make(map[uint8]*EPSBearer),
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.ues[ue.ID] = ue

	return ue
}

// AdoptUE inserts an existing UE context under this eNB, modelling the UE
// arriving at a target eNB after an S1 handover. The context keeps its identity,
// credentials, and EPS NAS security state.
func (e *ENBContext) AdoptUE(ue *UEEPSContext) {
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

	if _, ok := e.ues[ueID]; !ok {
		return false
	}

	delete(e.ues, ueID)

	return true
}
