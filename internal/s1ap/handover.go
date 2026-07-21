// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"github.com/ellanetworks/core/s1ap"
)

// The container is opaque at S1AP (TS 36.413 §9.1.5), so one octet satisfies the mandatory IE.
var handoverContainerStub = s1ap.TransparentContainer{0x00}

type HandoverRequiredParams struct {
	MMEUES1APID       uint32
	ENBUES1APID       uint32
	CauseRadioNetwork int64

	TargetMCC       string
	TargetMNC       string
	TargetTAC       string
	TargetENBID     uint32
	TargetENBIDKind ENBIDKind
}

func BuildHandoverRequired(p HandoverRequiredParams) ([]byte, error) {
	plmn, err := encodePLMN(p.TargetMCC, p.TargetMNC)
	if err != nil {
		return nil, err
	}

	tac, err := parseTAC(p.TargetTAC)
	if err != nil {
		return nil, err
	}

	m := &s1ap.HandoverRequired{
		MMEUES1APID:  s1ap.MMEUES1APID(p.MMEUES1APID),
		ENBUES1APID:  s1ap.ENBUES1APID(p.ENBUES1APID),
		HandoverType: s1ap.HandoverTypeIntraLTE,
		Cause:        s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: int(p.CauseRadioNetwork)},
		TargetID: s1ap.TargetID{
			TargeteNBID: s1ap.TargeteNBID{
				GlobalENBID: s1ap.GlobalENBID{
					PLMNIdentity: plmn,
					ENBID:        s1ap.ENBID{Kind: p.TargetENBIDKind, Value: p.TargetENBID},
				},
				SelectedTAI: s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(tac)},
			},
		},
		SourceToTarget: handoverContainerStub,
	}

	return m.Marshal()
}

type HandoverAdmittedERAB struct {
	ERABID uint8
	DLTeid uint32
	DLAddr string
}

type HandoverRequestAcknowledgeParams struct {
	MMEUES1APID   uint32
	ENBUES1APID   uint32
	Admitted      []HandoverAdmittedERAB
	FailedERABIDs []uint8
}

func BuildHandoverRequestAcknowledge(p HandoverRequestAcknowledgeParams) ([]byte, error) {
	admitted := make([]s1ap.ERABAdmittedItem, 0, len(p.Admitted))

	for _, e := range p.Admitted {
		addr, err := parseTransportAddr(e.DLAddr)
		if err != nil {
			return nil, err
		}

		admitted = append(admitted, s1ap.ERABAdmittedItem{
			ERABID:                s1ap.ERABID(e.ERABID),
			TransportLayerAddress: s1ap.TransportLayerAddress(addr),
			GTPTEID:               s1ap.GTPTEID(e.DLTeid),
		})
	}

	failed := make([]s1ap.ERABItem, 0, len(p.FailedERABIDs))
	for _, id := range p.FailedERABIDs {
		failed = append(failed, s1ap.ERABItem{
			ERABID: s1ap.ERABID(id),
			Cause:  s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: int(CauseRadioNetworkHOFailureInTarget)},
		})
	}

	m := &s1ap.HandoverRequestAcknowledge{
		MMEUES1APID:       s1ap.MMEUES1APID(p.MMEUES1APID),
		ENBUES1APID:       s1ap.ENBUES1APID(p.ENBUES1APID),
		ERABAdmitted:      admitted,
		ERABFailedToSetup: failed,
		TargetToSource:    handoverContainerStub,
	}

	return m.Marshal()
}

type HandoverNotifyParams struct {
	MMEUES1APID uint32
	ENBUES1APID uint32
	MCC         string
	MNC         string
	TAC         string
	CellID      uint32
}

func BuildHandoverNotify(p HandoverNotifyParams) ([]byte, error) {
	plmn, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, err
	}

	tac, err := parseTAC(p.TAC)
	if err != nil {
		return nil, err
	}

	m := &s1ap.HandoverNotify{
		MMEUES1APID: s1ap.MMEUES1APID(p.MMEUES1APID),
		ENBUES1APID: s1ap.ENBUES1APID(p.ENBUES1APID),
		EUTRANCGI:   s1ap.EUTRANCGI{PLMNIdentity: plmn, CellID: p.CellID},
		TAI:         s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(tac)},
	}

	return m.Marshal()
}

func BuildHandoverCancel(mmeUES1APID, enbUES1APID uint32, cause int64) ([]byte, error) {
	m := &s1ap.HandoverCancel{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUES1APID),
		ENBUES1APID: s1ap.ENBUES1APID(enbUES1APID),
		Cause:       s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: int(cause)},
	}

	return m.Marshal()
}

func BuildHandoverFailure(mmeUES1APID uint32, cause int64) ([]byte, error) {
	m := &s1ap.HandoverFailure{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUES1APID),
		Cause:       s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: int(cause)},
	}

	return m.Marshal()
}

// The container is opaque at S1AP (TS 36.413 §8.4.6), so one octet stands in for a nil one.
func BuildENBStatusTransfer(mmeUES1APID, enbUES1APID uint32, container []byte) ([]byte, error) {
	if container == nil {
		container = []byte{0x00}
	}

	m := &s1ap.ENBStatusTransfer{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUES1APID),
		ENBUES1APID: s1ap.ENBUES1APID(enbUES1APID),
		Container:   s1ap.StatusTransferContainer(container),
	}

	return m.Marshal()
}
