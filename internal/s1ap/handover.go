// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"net"

	"github.com/ellanetworks/core/s1ap"
)

// S1AP radio-network Cause values for the S1 handover procedures (TS 36.413
// §9.2.1.3), matching the values the MME emits.
const (
	CauseHandoverDesirableForRadioReasons = 16
	CauseHandoverCancelled                = 4
	CauseHOFailureInTarget                = 6
)

// handoverContainerStub is the opaque source/target eNB transparent container.
// The MME relays it verbatim between the eNBs (TS 36.413 §8.4), so its content
// is immaterial to the procedure and a single octet satisfies the mandatory IE.
var handoverContainerStub = s1ap.TransparentContainer{0x00}

// HandoverRequiredParams are the inputs to build a HANDOVER REQUIRED the source
// eNB sends to start S1 handover preparation toward the target eNB (TS 36.413
// §8.4.1). The target identity fields are the target eNB's own PLMN/TAC/eNB-ID.
type HandoverRequiredParams struct {
	MMEUES1APID uint32
	ENBUES1APID uint32
	Cause       int

	TargetMCC   string
	TargetMNC   string
	TargetTAC   uint16
	TargetENBID uint32
}

func BuildHandoverRequired(p HandoverRequiredParams) ([]byte, error) {
	plmn, err := encodePLMN(p.TargetMCC, p.TargetMNC)
	if err != nil {
		return nil, err
	}

	m := &s1ap.HandoverRequired{
		MMEUES1APID:  s1ap.MMEUES1APID(p.MMEUES1APID),
		ENBUES1APID:  s1ap.ENBUES1APID(p.ENBUES1APID),
		HandoverType: s1ap.HandoverTypeIntraLTE,
		Cause:        s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: p.Cause},
		TargetID: s1ap.TargetID{
			TargeteNBID: s1ap.TargeteNBID{
				GlobalENBID: s1ap.GlobalENBID{
					PLMNIdentity: plmn,
					ENBID:        s1ap.ENBID{Kind: s1ap.ENBIDMacro, Value: p.TargetENBID},
				},
				SelectedTAI: s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(p.TargetTAC)},
			},
		},
		SourceToTarget: handoverContainerStub,
	}

	return m.Marshal()
}

// HandoverAdmittedERAB is one E-RAB the target eNB admits in a HANDOVER REQUEST
// ACKNOWLEDGE, with the downlink S1-U endpoint it will receive user data on.
type HandoverAdmittedERAB struct {
	ERABID uint8
	DLTeid uint32
	DLAddr string
}

// HandoverRequestAcknowledgeParams are the inputs to build a HANDOVER REQUEST
// ACKNOWLEDGE the target eNB sends after admitting the incoming UE's bearers
// (TS 36.413 §8.4.2). FailedERABIDs lists bearers the target did not admit.
type HandoverRequestAcknowledgeParams struct {
	MMEUES1APID   uint32
	ENBUES1APID   uint32
	Admitted      []HandoverAdmittedERAB
	FailedERABIDs []uint8
}

func BuildHandoverRequestAcknowledge(p HandoverRequestAcknowledgeParams) ([]byte, error) {
	admitted := make([]s1ap.ERABAdmittedItem, 0, len(p.Admitted))

	for _, e := range p.Admitted {
		addr := net.ParseIP(e.DLAddr)
		if v4 := addr.To4(); v4 != nil {
			addr = v4
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
			Cause:  s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: CauseHOFailureInTarget},
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

// HandoverNotifyParams are the inputs to build a HANDOVER NOTIFY the target eNB
// sends once the UE has arrived, reporting its new location (TS 36.413 §8.4.3).
type HandoverNotifyParams struct {
	MMEUES1APID uint32
	ENBUES1APID uint32
	MCC         string
	MNC         string
	TAC         uint16
	CellID      uint32
}

func BuildHandoverNotify(p HandoverNotifyParams) ([]byte, error) {
	plmn, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, err
	}

	m := &s1ap.HandoverNotify{
		MMEUES1APID: s1ap.MMEUES1APID(p.MMEUES1APID),
		ENBUES1APID: s1ap.ENBUES1APID(p.ENBUES1APID),
		EUTRANCGI:   s1ap.EUTRANCGI{PLMNIdentity: plmn, CellID: p.CellID},
		TAI:         s1ap.TAI{PLMNIdentity: plmn, TAC: s1ap.TAC(p.TAC)},
	}

	return m.Marshal()
}

// BuildHandoverCancel builds a HANDOVER CANCEL the source eNB sends to abort a
// handover it has prepared (TS 36.413 §8.4.5).
func BuildHandoverCancel(mmeUES1APID, enbUES1APID uint32, cause int) ([]byte, error) {
	m := &s1ap.HandoverCancel{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUES1APID),
		ENBUES1APID: s1ap.ENBUES1APID(enbUES1APID),
		Cause:       s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: cause},
	}

	return m.Marshal()
}

// BuildHandoverFailure builds a HANDOVER FAILURE the target eNB sends when it
// cannot admit the incoming UE, aborting resource allocation (TS 36.413 §8.4.2).
func BuildHandoverFailure(mmeUES1APID uint32, cause int) ([]byte, error) {
	m := &s1ap.HandoverFailure{
		MMEUES1APID: s1ap.MMEUES1APID(mmeUES1APID),
		Cause:       s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: cause},
	}

	return m.Marshal()
}

// BuildENBStatusTransfer builds an eNB STATUS TRANSFER the source eNB sends
// after the Handover Command to relay PDCP status to the target (TS 36.413
// §8.4.6). The container is opaque to the MME, which relays it as an MME Status
// Transfer.
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
