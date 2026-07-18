// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"github.com/ellanetworks/core/s1ap"
)

type PathSwitchRequestParams struct {
	ENBUES1APID       uint32
	SourceMMEUES1APID uint32
	ERABID            uint8
	TargetS1UAddr     string
	TargetTEID        uint32
	MCC, MNC          string
	TAC               string
	CellID            uint32

	EncryptionAlgorithms          uint16
	IntegrityProtectionAlgorithms uint16

	Duplicate bool
}

func BuildPathSwitchRequest(p PathSwitchRequestParams) ([]byte, error) {
	plmn, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, err
	}

	addr, err := parseTransportAddr(p.TargetS1UAddr)
	if err != nil {
		return nil, err
	}

	tac, err := parseTAC(p.TAC)
	if err != nil {
		return nil, err
	}

	item := s1ap.ERABToBeSwitchedDLItem{
		ERABID:                s1ap.ERABID(p.ERABID),
		TransportLayerAddress: s1ap.TransportLayerAddress(addr),
		GTPTEID:               s1ap.GTPTEID(p.TargetTEID),
	}

	items := []s1ap.ERABToBeSwitchedDLItem{item}
	if p.Duplicate {
		items = append(items, item)
	}

	m := &s1ap.PathSwitchRequest{
		ENBUES1APID:        s1ap.ENBUES1APID(p.ENBUES1APID),
		ERABToBeSwitchedDL: items,
		SourceMMEUES1APID:  s1ap.MMEUES1APID(p.SourceMMEUES1APID),
		EUTRANCGI:          s1ap.EUTRANCGI{PLMNIdentity: plmn, CellID: p.CellID},
		TAI:                s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(tac)},
		UESecurityCapabilities: s1ap.UESecurityCapabilities{
			EncryptionAlgorithms:          p.EncryptionAlgorithms,
			IntegrityProtectionAlgorithms: p.IntegrityProtectionAlgorithms,
		},
	}

	return m.Marshal()
}
