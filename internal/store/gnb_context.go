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
	nextUeID    atomic.Int64
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
	N3GnbIP     string `json:"n3_gnb_ip"`
	DLTeid      uint32 `json:"dl_teid"`
	QFI         uint8  `json:"qfi"`
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
