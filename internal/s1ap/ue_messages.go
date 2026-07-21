// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"github.com/ellanetworks/core/s1ap"
)

type STMSIParams struct {
	MMEC  uint8
	MTMSI uint32
}

type InitialUEMessageParams struct {
	ENBUES1APID           uint32
	NASPDU                []byte
	MCC, MNC              string
	TAC                   string
	CellID                uint32
	STMSI                 *STMSIParams
	RRCEstablishmentCause *int64
}

func BuildInitialUEMessage(p InitialUEMessageParams) ([]byte, error) {
	plmn, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, err
	}

	rrcCause := s1ap.RRCCauseMOSignalling
	if p.RRCEstablishmentCause != nil {
		rrcCause = s1ap.RRCEstablishmentCause(*p.RRCEstablishmentCause)
	}

	tac, err := parseTAC(p.TAC)
	if err != nil {
		return nil, err
	}

	m := &s1ap.InitialUEMessage{
		ENBUES1APID:           s1ap.ENBUES1APID(p.ENBUES1APID),
		NASPDU:                p.NASPDU,
		TAI:                   s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(tac)},
		EUTRANCGI:             s1ap.EUTRANCGI{PLMNIdentity: plmn, CellID: p.CellID},
		RRCEstablishmentCause: rrcCause,
	}

	if p.STMSI != nil {
		m.STMSI = &s1ap.STMSI{MMEC: p.STMSI.MMEC, MTMSI: p.STMSI.MTMSI}
	}

	return m.Marshal()
}

func BuildUEContextReleaseRequest(mmeUEID, enbUEID uint32, cause int64) ([]byte, error) {
	m := &s1ap.UEContextReleaseRequest{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID: s1ap.ENBUES1APID(enbUEID),
		Cause:       radioNetworkCause(cause),
	}

	return m.Marshal()
}

func BuildInitialContextSetupFailure(mmeUEID, enbUEID uint32, cause int64) ([]byte, error) {
	return (&s1ap.InitialContextSetupFailure{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID: s1ap.ENBUES1APID(enbUEID),
		Cause:       s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: int(cause)},
	}).Marshal()
}

func BuildERABModifyResponse(mmeUEID, enbUEID uint32, modified []uint8) ([]byte, error) {
	items := make([]s1ap.ERABModifyItemBearerModRes, 0, len(modified))
	for _, ebi := range modified {
		items = append(items, s1ap.ERABModifyItemBearerModRes{ERABID: s1ap.ERABID(ebi)})
	}

	return (&s1ap.ERABModifyResponse{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID: s1ap.ENBUES1APID(enbUEID),
		ERABModify:  items,
	}).Marshal()
}

func BuildErrorIndication(mmeUEID, enbUEID uint32, cause int64) ([]byte, error) {
	mme := s1ap.MMEUES1APID(mmeUEID)
	enb := s1ap.ENBUES1APID(enbUEID)
	c := s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: int(cause)}

	return (&s1ap.ErrorIndication{
		MMEUES1APID: &mme,
		ENBUES1APID: &enb,
		Cause:       &c,
	}).Marshal()
}

func BuildUEContextReleaseComplete(mmeUEID, enbUEID uint32) ([]byte, error) {
	return (&s1ap.UEContextReleaseComplete{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID: s1ap.ENBUES1APID(enbUEID),
	}).Marshal()
}

func BuildUECapabilityInfoIndication(mmeUEID, enbUEID uint32, radioCapability []byte) ([]byte, error) {
	return (&s1ap.UECapabilityInfoIndication{
		MMEUES1APID:       s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID:       s1ap.ENBUES1APID(enbUEID),
		UERadioCapability: radioCapability,
	}).Marshal()
}

type UplinkNASTransportParams struct {
	MMEUES1APID uint32
	ENBUES1APID uint32
	NASPDU      []byte
	MCC, MNC    string
	TAC         string
	CellID      uint32
}

func BuildUplinkNASTransport(p UplinkNASTransportParams) ([]byte, error) {
	plmn, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, err
	}

	tac, err := parseTAC(p.TAC)
	if err != nil {
		return nil, err
	}

	m := &s1ap.UplinkNASTransport{
		MMEUES1APID: s1ap.MMEUES1APID(p.MMEUES1APID),
		ENBUES1APID: s1ap.ENBUES1APID(p.ENBUES1APID),
		NASPDU:      p.NASPDU,
		EUTRANCGI:   s1ap.EUTRANCGI{PLMNIdentity: plmn, CellID: p.CellID},
		TAI:         s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(tac)},
	}

	return m.Marshal()
}

type InitialContextSetupResponseParams struct {
	MMEUES1APID uint32
	ENBUES1APID uint32
	ERABID      uint8
	ENBN3Addr   string
	GTPTEID     uint32
}

func BuildInitialContextSetupResponse(p InitialContextSetupResponseParams) ([]byte, error) {
	addr, err := parseTransportAddr(p.ENBN3Addr)
	if err != nil {
		return nil, err
	}

	m := &s1ap.InitialContextSetupResponse{
		MMEUES1APID: s1ap.MMEUES1APID(p.MMEUES1APID),
		ENBUES1APID: s1ap.ENBUES1APID(p.ENBUES1APID),
		ERABSetup: []s1ap.ERABSetupItemCtxtSURes{{
			ERABID:                s1ap.ERABID(p.ERABID),
			TransportLayerAddress: s1ap.TransportLayerAddress(addr),
			GTPTEID:               s1ap.GTPTEID(p.GTPTEID),
		}},
	}

	return m.Marshal()
}

func BuildERABReleaseResponse(mmeUEID, enbUEID uint32, erabID uint8) ([]byte, error) {
	m := &s1ap.ERABReleaseResponse{
		MMEUES1APID:  s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID:  s1ap.ENBUES1APID(enbUEID),
		ERABReleased: []s1ap.ERABReleaseItemBearerRelComp{{ERABID: s1ap.ERABID(erabID)}},
	}

	return m.Marshal()
}

func BuildERABSetupResponse(p InitialContextSetupResponseParams) ([]byte, error) {
	addr, err := parseTransportAddr(p.ENBN3Addr)
	if err != nil {
		return nil, err
	}

	m := &s1ap.ERABSetupResponse{
		MMEUES1APID: s1ap.MMEUES1APID(p.MMEUES1APID),
		ENBUES1APID: s1ap.ENBUES1APID(p.ENBUES1APID),
		ERABSetup: []s1ap.ERABSetupItemBearerSURes{{
			ERABID:                s1ap.ERABID(p.ERABID),
			TransportLayerAddress: s1ap.TransportLayerAddress(addr),
			GTPTEID:               s1ap.GTPTEID(p.GTPTEID),
		}},
	}

	return m.Marshal()
}
