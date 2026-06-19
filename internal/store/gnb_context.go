// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"sync"
	"sync/atomic"
)

type GnBContext struct {
	ID    string
	MCC   string
	MNC   string
	SST   int32
	SD    string
	TAC   string
	GnbID string
	Name  string

	Slices []SliceConfig

	mu          sync.RWMutex
	UEs         map[string]*UEContext
	nextRanUeID atomic.Int64

	NGAPIDs     map[int64]int64
	PDUSessions map[int64]map[int64]*PDUSessionInfo
	UEAmbr      map[int64]*UEAmbrInfo
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
func (g *GnBContext) GetPDUSession(ranUeID, pduSessionID int64) (*PDUSessionInfo, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	sessions, ok := g.PDUSessions[ranUeID]
	if !ok {
		return nil, false
	}

	info, ok := sessions[pduSessionID]

	return info, ok
}

type UEAmbrInfo struct {
	UplinkBps   int64 `json:"uplink_bps"`
	DownlinkBps int64 `json:"downlink_bps"`
}

func NewGnBContext(id, mcc, mnc, tac, gnbID, name string, sst int32, sd string, slices []SliceConfig) *GnBContext {
	return &GnBContext{
		ID:          id,
		MCC:         mcc,
		MNC:         mnc,
		SST:         sst,
		SD:          sd,
		TAC:         tac,
		GnbID:       gnbID,
		Name:        name,
		Slices:      slices,
		UEs:         make(map[string]*UEContext),
		NGAPIDs:     make(map[int64]int64),
		PDUSessions: make(map[int64]map[int64]*PDUSessionInfo),
		UEAmbr:      make(map[int64]*UEAmbrInfo),
	}
}

func (g *GnBContext) AllocateRanUeNgapID() int64 {
	return g.nextRanUeID.Add(1)
}

func (g *GnBContext) UpdateNGAPIDs(ranUeID, amfUeID int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.NGAPIDs[ranUeID] = amfUeID
}

func (g *GnBContext) GetAMFUENGAPID(ranUeID int64) (int64, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	id, ok := g.NGAPIDs[ranUeID]
	return id, ok
}

func (g *GnBContext) StorePDUSession(ranUeID int64, info *PDUSessionInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.PDUSessions[ranUeID] == nil {
		g.PDUSessions[ranUeID] = make(map[int64]*PDUSessionInfo)
	}
	g.PDUSessions[ranUeID][info.PDUSessionID] = info
}

func (g *GnBContext) StoreUEAmbr(ranUeID int64, ambr *UEAmbrInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.UEAmbr[ranUeID] = ambr
}

func (g *GnBContext) CreateUE(ue *UEContext) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.UEs[ue.ID] = ue
}

func (g *GnBContext) GetUE(ueID string) (*UEContext, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ue, ok := g.UEs[ueID]
	return ue, ok
}

func (g *GnBContext) DeleteUE(ueID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.UEs[ueID]; !ok {
		return false
	}
	delete(g.UEs, ueID)
	return true
}

func (g *GnBContext) ListUEs() []*UEContext {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ues := make([]*UEContext, 0, len(g.UEs))
	for _, ue := range g.UEs {
		ues = append(ues, ue)
	}
	return ues
}
