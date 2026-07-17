// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

type EPSBearer struct {
	EBI    uint8
	PTI    uint8
	APN    string
	UEIP   string
	ULTeid uint32
	SGWIP  string
	DLTeid uint32
}

type UEEPSContext struct {
	ID   string
	IMSI string
	K    string
	OPc  string
	AMF  string
	SQN  string

	ENBUES1APID uint32
	MMEUES1APID uint32
	MMEIDKnown  bool

	UENetworkCapability []byte // nil uses the default

	RAND []byte
	AUTN []byte

	Kasme          []byte
	KnasEnc        [16]byte
	KnasInt        [16]byte
	EEA            uint8
	EIA            uint8
	ULCount        uint32
	DLCount        uint32
	SecurityActive bool

	LastUplinkNAS []byte

	EPSBearerID uint8
	PTI         uint8
	ERABID      uint8

	KSI uint8

	ULTeid uint32
	SGWIP  string
	DLTeid uint32
	UEIP   string

	// Additional PDN connections beyond the default bearer, keyed by EPS bearer identity.
	Bearers map[uint8]*EPSBearer

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

func (u *UEEPSContext) NextUL() uint32 {
	c := u.ULCount
	u.ULCount++

	return c
}

func (u *UEEPSContext) NextDL() uint32 {
	c := u.DLCount
	u.DLCount++

	return c
}
