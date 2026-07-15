// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

// EPSBearer is an additional PDN connection's default EPS bearer: its identity,
// APN, assigned IP, and S1-U user-plane tunnel (TS 24.301 §6.5.1).
type EPSBearer struct {
	EBI    uint8
	PTI    uint8
	APN    string
	UEIP   string
	ULTeid uint32 // S-GW/UPF uplink endpoint TEID
	UPFIP  string // S-GW/UPF S1-U address
	DLTeid uint32 // eNB downlink TEID
}

// UEEPSContext is an emulated UE's EPS attach state on an eNB.
type UEEPSContext struct {
	ID   string
	IMSI string // 15-digit IMSI
	K    string
	OPc  string
	AMF  string
	SQN  string

	ENBUES1APID uint32
	MMEUES1APID uint32
	MMEIDKnown  bool

	// UENetworkCapability is the advertised EEA/EIA support; nil uses the default.
	UENetworkCapability []byte

	// Last authentication challenge, stored from the Authentication Request so the
	// response can be computed without the client re-supplying it.
	RAND []byte
	AUTN []byte

	// EPS NAS security context (TS 33.401 §6.1). Counts are per-direction and
	// increment per protected message; both reset to 0 when the context activates.
	Kasme          []byte
	KnasEnc        [16]byte
	KnasInt        [16]byte
	EEA            uint8
	EIA            uint8
	ULCount        uint32
	DLCount        uint32
	SecurityActive bool

	// LastUplinkNAS is the most recent uplink NAS PDU sent, kept so it can be
	// replayed to test the MME's NAS replay protection.
	LastUplinkNAS []byte

	// Default-bearer state learned from the Attach Accept / Initial Context Setup.
	EPSBearerID uint8
	PTI         uint8
	ERABID      uint8

	// NAS key set identifier the MME assigned in the Authentication Request.
	KSI uint8

	// S1-U user-plane tunnel for the default bearer: the S-GW/UPF uplink endpoint
	// (from the Initial Context Setup Request), the eNB downlink TEID (what the eNB
	// advertised), and the UE's assigned IP (from the Attach Accept).
	ULTeid uint32
	UPFIP  string
	DLTeid uint32
	UEIP   string

	// Bearers holds additional PDN connections beyond the default bearer, keyed by
	// their EPS bearer identity. Each is a separate default EPS bearer to a
	// distinct APN, with its own IP and S1-U tunnel (TS 24.301 §6.5.1).
	Bearers map[uint8]*EPSBearer

	// GUTI assigned in the Attach Accept, used as the mobile identity in a
	// UE-originating Detach Request.
	GUTIMCC     string
	GUTIMNC     string
	GUTIGroupID uint16
	GUTICode    uint8
	GUTIMTMSI   uint32
}

type CreateUEEPSOpts struct {
	IMSI string
	K    string
	OPc  string
	AMF  string
	SQN  string
}

func NewUEEPSContext(id string, enbUES1APID uint32, opts *CreateUEEPSOpts) *UEEPSContext {
	return &UEEPSContext{
		ID:          id,
		IMSI:        opts.IMSI,
		K:           opts.K,
		OPc:         opts.OPc,
		AMF:         opts.AMF,
		SQN:         opts.SQN,
		ENBUES1APID: enbUES1APID,
		Bearers:     make(map[uint8]*EPSBearer),
	}
}

// NextUL returns the current uplink NAS COUNT and advances it.
func (u *UEEPSContext) NextUL() uint32 {
	c := u.ULCount
	u.ULCount++

	return c
}

// NextDL returns the current downlink NAS COUNT and advances it.
func (u *UEEPSContext) NextDL() uint32 {
	c := u.DLCount
	u.DLCount++

	return c
}
