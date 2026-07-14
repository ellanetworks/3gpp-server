// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"github.com/ellanetworks/core/s1ap"
)

// PathSwitchRequestParams are the inputs to build a PATH SWITCH REQUEST the
// target eNB sends after an X2 handover to switch the S1-U downlink to itself
// (TS 36.413 §9.1.5.8).
type PathSwitchRequestParams struct {
	ENBUES1APID       uint32 // the target eNB's new eNB UE S1AP ID
	SourceMMEUES1APID uint32 // the MME UE S1AP ID the source eNB held
	ERABID            uint8
	TargetS1UAddr     string // the target eNB's S1-U transport address
	TargetTEID        uint32 // the target eNB's downlink TEID
	MCC, MNC          string
	TAC               uint16
	CellID            uint32

	// EncryptionAlgorithms and IntegrityProtectionAlgorithms are the UE security
	// capabilities the target eNB reports (TS 36.413 §9.2.1.40).
	EncryptionAlgorithms          uint16
	IntegrityProtectionAlgorithms uint16

	// Duplicate emits the E-RAB to-be-switched item twice, an abnormal condition
	// the MME must reject with cause multiple-E-RAB-ID-instances (TS 36.413).
	Duplicate bool
}

// BuildPathSwitchRequest builds a PATH SWITCH REQUEST switching a single E-RAB's
// downlink to the target eNB endpoint it carries.
func BuildPathSwitchRequest(p PathSwitchRequestParams) ([]byte, error) {
	plmn, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, err
	}

	addr, err := parseTransportAddr(p.TargetS1UAddr)
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
		TAI:                s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(p.TAC)},
		UESecurityCapabilities: s1ap.UESecurityCapabilities{
			EncryptionAlgorithms:          p.EncryptionAlgorithms,
			IntegrityProtectionAlgorithms: p.IntegrityProtectionAlgorithms,
		},
	}

	return m.Marshal()
}
