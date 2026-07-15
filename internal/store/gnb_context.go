// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"sync"
	"sync/atomic"
)

// GNBContext is an emulated gNB's NG-C association state, including the UE
// contexts attached through it.
type GNBContext struct {
	ID    string
	MCC   string
	MNC   string
	SST   int32
	SD    string
	TAC   string
	GNBID string
	Name  string

	// N3Addr is the gNB's N3 transport address, advertised as the downlink
	// endpoint in the PDU Session Resource Setup Response.
	N3Addr string

	Slices []SliceConfig

	mu          sync.RWMutex
	ues         map[string]*UEContext
	nextRanUeID atomic.Int64

	pduSessions map[int64]map[int64]*PDUSessionInfo
}

type SliceConfig struct {
	SST int32  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

type PDUSessionInfo struct {
	PDUSessionID int64  `json:"pdu_session_id"`
	N3GnbIP      string `json:"n3_gnb_ip"`
	DLTeid       uint32 `json:"dl_teid"`
	QFI          uint8  `json:"qfi"`

	// User-plane (N3 GTP-U) state, populated when the gNB terminates the data
	// path: the UPF's uplink tunnel (learned from the PDU Session Resource Setup
	// Request transfer) and the UE's assigned IP (from the Establishment Accept).
	ULTeid uint32 `json:"ul_teid,omitempty"`
	UPFIP  string `json:"upf_ip,omitempty"`
	UEIP   string `json:"ue_ip,omitempty"`
}

// GetPDUSession returns the stored session state for a UE's PDU session.
func (g *GNBContext) GetPDUSession(ranUeID, pduSessionID int64) (*PDUSessionInfo, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	sessions, ok := g.pduSessions[ranUeID]
	if !ok {
		return nil, false
	}

	info, ok := sessions[pduSessionID]

	return info, ok
}

func NewGNBContext(id, mcc, mnc, tac, gnbID, name string, sst int32, sd string, slices []SliceConfig) *GNBContext {
	return &GNBContext{
		ID:          id,
		MCC:         mcc,
		MNC:         mnc,
		SST:         sst,
		SD:          sd,
		TAC:         tac,
		GNBID:       gnbID,
		Name:        name,
		Slices:      slices,
		ues:         make(map[string]*UEContext),
		pduSessions: make(map[int64]map[int64]*PDUSessionInfo),
	}
}

func (g *GNBContext) AllocateRanUeNgapID() int64 {
	return g.nextRanUeID.Add(1)
}

func (g *GNBContext) StorePDUSession(ranUeID int64, info *PDUSessionInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pduSessions[ranUeID] == nil {
		g.pduSessions[ranUeID] = make(map[int64]*PDUSessionInfo)
	}
	g.pduSessions[ranUeID][info.PDUSessionID] = info
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
	ue, ok := g.ues[ueID]
	if !ok {
		return false
	}

	delete(g.ues, ueID)
	delete(g.pduSessions, ue.RanUeNgapID)

	return true
}

// MigrateUE moves a UE context from this gNB to target, modelling the UE
// arriving at the target after an N2 handover. The context keeps its identity,
// credentials, and 5G NAS security state; non-nil IDs replace its NGAP UE
// identities on the target. The source's ranUeID-keyed session state is purged
// under the UE's current RAN-UE-NGAP-ID, before any new ID is applied.
func (g *GNBContext) MigrateUE(target *GNBContext, ue *UEContext, ranUeNgapID, amfUeNgapID *int64) {
	g.mu.Lock()
	g.deleteUELocked(ue.ID)
	g.mu.Unlock()

	if ranUeNgapID != nil {
		ue.RanUeNgapID = *ranUeNgapID
	}

	if amfUeNgapID != nil {
		ue.AmfUeNgapID = *amfUeNgapID
	}

	target.CreateUE(ue)
}
