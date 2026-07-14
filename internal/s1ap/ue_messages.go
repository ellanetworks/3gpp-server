// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"net"

	"github.com/ellanetworks/core/s1ap"
)

// STMSIParams identifies an idle UE re-establishing (e.g. a Service Request).
type STMSIParams struct {
	MMEC  uint8
	MTMSI uint32
}

// InitialUEMessageParams are the inputs to build an Initial UE Message carrying a
// UE's first NAS message (TS 36.413 §9.1.7.1).
type InitialUEMessageParams struct {
	ENBUES1APID uint32
	NASPDU      []byte
	MCC, MNC    string
	TAC         uint16
	CellID      uint32
	STMSI       *STMSIParams // present when the UE re-establishes with an S-TMSI
}

// BuildInitialUEMessage builds an Initial UE Message with RRC establishment cause
// mo-Signalling (an attach).
func BuildInitialUEMessage(p InitialUEMessageParams) ([]byte, error) {
	plmn, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, err
	}

	m := &s1ap.InitialUEMessage{
		ENBUES1APID:           s1ap.ENBUES1APID(p.ENBUES1APID),
		NASPDU:                p.NASPDU,
		TAI:                   s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(p.TAC)},
		EUTRANCGI:             s1ap.EUTRANCGI{PLMNIdentity: plmn, CellID: p.CellID},
		RRCEstablishmentCause: s1ap.RRCCauseMOSignalling,
	}

	if p.STMSI != nil {
		m.STMSI = &s1ap.STMSI{MMEC: p.STMSI.MMEC, MTMSI: p.STMSI.MTMSI}
	}

	return m.Marshal()
}

// CauseRadioUserInactivity is the S1AP radio-network cause "user-inactivity"
// (TS 36.413 §9.2.1.3), the typical cause for an eNB-requested release.
const CauseRadioUserInactivity uint8 = 20

// BuildUEContextReleaseRequest builds the eNB's request to release a UE's S1
// context, e.g. on inactivity (TS 36.413 §9.1.4.5) — moving the UE to ECM-IDLE.
// cause is the radio-network Cause value the eNB reports.
func BuildUEContextReleaseRequest(mmeUEID, enbUEID uint32, cause uint8) ([]byte, error) {
	m := &s1ap.UEContextReleaseRequest{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID: s1ap.ENBUES1APID(enbUEID),
		Cause:       s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: int(cause)},
	}

	return m.Marshal()
}

// BuildErrorIndication builds an eNB-originated ERROR INDICATION reporting a
// protocol error for the UE-associated connection (TS 36.413 §8.6.1).
func BuildErrorIndication(mmeUEID, enbUEID uint32, cause int) ([]byte, error) {
	mme := s1ap.MMEUES1APID(mmeUEID)
	enb := s1ap.ENBUES1APID(enbUEID)
	c := s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: cause}

	return (&s1ap.ErrorIndication{
		MMEUES1APID: &mme,
		ENBUES1APID: &enb,
		Cause:       &c,
	}).Marshal()
}

// BuildUEContextReleaseComplete builds the eNB's acknowledgement of a UE Context
// Release Command (TS 36.413 §9.1.4.7).
func BuildUEContextReleaseComplete(mmeUEID, enbUEID uint32) ([]byte, error) {
	return (&s1ap.UEContextReleaseComplete{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID: s1ap.ENBUES1APID(enbUEID),
	}).Marshal()
}

// BuildUECapabilityInfoIndication builds the eNB's indication of the UE radio
// capability to the MME (TS 36.413 §8.9). The MME stores it and replays it in a
// later Initial Context Setup Request.
func BuildUECapabilityInfoIndication(mmeUEID, enbUEID uint32, radioCapability []byte) ([]byte, error) {
	return (&s1ap.UECapabilityInfoIndication{
		MMEUES1APID:       s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID:       s1ap.ENBUES1APID(enbUEID),
		UERadioCapability: radioCapability,
	}).Marshal()
}

// UplinkNASTransportParams are the inputs to relay a UE NAS message on an
// established UE context (TS 36.413 §9.1.7.3).
type UplinkNASTransportParams struct {
	MMEUES1APID uint32
	ENBUES1APID uint32
	NASPDU      []byte
	MCC, MNC    string
	TAC         uint16
	CellID      uint32
}

// BuildUplinkNASTransport builds an Uplink NAS Transport message.
func BuildUplinkNASTransport(p UplinkNASTransportParams) ([]byte, error) {
	plmn, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, err
	}

	m := &s1ap.UplinkNASTransport{
		MMEUES1APID: s1ap.MMEUES1APID(p.MMEUES1APID),
		ENBUES1APID: s1ap.ENBUES1APID(p.ENBUES1APID),
		NASPDU:      p.NASPDU,
		EUTRANCGI:   s1ap.EUTRANCGI{PLMNIdentity: plmn, CellID: p.CellID},
		TAI:         s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(p.TAC)},
	}

	return m.Marshal()
}

// InitialContextSetupResponseParams are the inputs for the eNB's acknowledgement
// of the default E-RAB setup (TS 36.413 §9.1.4.2).
type InitialContextSetupResponseParams struct {
	MMEUES1APID uint32
	ENBUES1APID uint32
	ERABID      uint8
	ENBN3Addr   string // eNB S1-U transport address
	GTPTEID     uint32 // eNB-side downlink TEID
}

// BuildInitialContextSetupResponse builds the eNB's Initial Context Setup
// Response, setting up the single default E-RAB with the eNB's S1-U endpoint.
func BuildInitialContextSetupResponse(p InitialContextSetupResponseParams) ([]byte, error) {
	addr := net.ParseIP(p.ENBN3Addr)
	if v4 := addr.To4(); v4 != nil {
		addr = v4
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

// BuildERABReleaseResponse builds the eNB's confirmation that it released the
// named E-RAB (TS 36.413 §9.1.3.5).
func BuildERABReleaseResponse(mmeUEID, enbUEID uint32, erabID uint8) ([]byte, error) {
	m := &s1ap.ERABReleaseResponse{
		MMEUES1APID:  s1ap.MMEUES1APID(mmeUEID),
		ENBUES1APID:  s1ap.ENBUES1APID(enbUEID),
		ERABReleased: []s1ap.ERABReleaseItemBearerRelComp{{ERABID: s1ap.ERABID(erabID)}},
	}

	return m.Marshal()
}

// BuildERABSetupResponse builds the eNB's acknowledgement of an E-RAB Setup
// Request, setting up the additional E-RAB with the eNB's S1-U endpoint
// (TS 36.413 §9.1.3.2).
func BuildERABSetupResponse(p InitialContextSetupResponseParams) ([]byte, error) {
	addr := net.ParseIP(p.ENBN3Addr)
	if v4 := addr.To4(); v4 != nil {
		addr = v4
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
