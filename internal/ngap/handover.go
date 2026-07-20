// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

type HandoverAdmittedSession struct {
	PDUSessionID int64
	DLTeid       uint32
	DLIP         string
	RawTransfer  []byte
}

type HandoverRequiredParams struct {
	AMFUENGAPID       int64
	RANUENGAPID       int64
	TargetGNBID       string
	MCC               string
	MNC               string
	TAC               string
	PDUSessionIDs     []int64
	CauseRadioNetwork int64
}

// The source-to-target container and per-session transfer are opaque to the AMF (TS 38.413 §8.4.1), so placeholders suffice.
func BuildHandoverRequired(p HandoverRequiredParams) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeHandoverPreparation
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentHandoverRequired
	im.Value.HandoverRequired = new(ngapType.HandoverRequired)

	ies := &im.Value.HandoverRequired.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.HandoverRequiredIEsValue {
		ie := ngapType.HandoverRequiredIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)
		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.HandoverRequiredIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: p.AMFUENGAPID}

	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.HandoverRequiredIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: p.RANUENGAPID}

	add(ngapType.ProtocolIEIDHandoverType, ngapType.CriticalityPresentReject,
		ngapType.HandoverRequiredIEsPresentHandoverType).HandoverType = &ngapType.HandoverType{Value: ngapType.HandoverTypePresentIntra5gs}

	add(ngapType.ProtocolIEIDCause, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverRequiredIEsPresentCause).Cause = &ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(p.CauseRadioNetwork)},
	}

	plmnID, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, fmt.Errorf("target PLMN: %w", err)
	}

	tacBytes, err := parseTAC(p.TAC)
	if err != nil {
		return nil, fmt.Errorf("target TAC: %w", err)
	}

	gnbIDBits := ngapConvert.HexToBitString(p.TargetGNBID, 24)
	add(ngapType.ProtocolIEIDTargetID, ngapType.CriticalityPresentReject,
		ngapType.HandoverRequiredIEsPresentTargetID).TargetID = &ngapType.TargetID{
		Present: ngapType.TargetIDPresentTargetRANNodeID,
		TargetRANNodeID: &ngapType.TargetRANNodeID{
			GlobalRANNodeID: ngapType.GlobalRANNodeID{
				Present: ngapType.GlobalRANNodeIDPresentGlobalGNBID,
				GlobalGNBID: &ngapType.GlobalGNBID{
					PLMNIdentity: ngapType.PLMNIdentity{Value: plmnID},
					GNBID:        ngapType.GNBID{Present: ngapType.GNBIDPresentGNBID, GNBID: &gnbIDBits},
				},
			},
			SelectedTAI: ngapType.TAI{
				PLMNIdentity: ngapType.PLMNIdentity{Value: plmnID},
				TAC:          ngapType.TAC{Value: tacBytes},
			},
		},
	}

	transfer, err := aper.MarshalWithParams(ngapType.HandoverRequiredTransfer{}, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal HandoverRequiredTransfer: %w", err)
	}

	list := &ngapType.PDUSessionResourceListHORqd{}
	for _, id := range p.PDUSessionIDs {
		list.List = append(list.List, ngapType.PDUSessionResourceItemHORqd{
			PDUSessionID:             ngapType.PDUSessionID{Value: id},
			HandoverRequiredTransfer: transfer,
		})
	}

	add(ngapType.ProtocolIEIDPDUSessionResourceListHORqd, ngapType.CriticalityPresentReject,
		ngapType.HandoverRequiredIEsPresentPDUSessionResourceListHORqd).PDUSessionResourceListHORqd = list

	add(ngapType.ProtocolIEIDSourceToTargetTransparentContainer, ngapType.CriticalityPresentReject,
		ngapType.HandoverRequiredIEsPresentSourceToTargetTransparentContainer).SourceToTargetTransparentContainer =
		&ngapType.SourceToTargetTransparentContainer{Value: []byte{0x00}}

	return ngap.Encoder(pdu)
}

type HandoverRequestAcknowledgeParams struct {
	AMFUENGAPID int64
	RANUENGAPID int64
	Sessions    []HandoverAdmittedSession
	Failed      []int64
}

func BuildHandoverRequestAcknowledge(p HandoverRequestAcknowledgeParams) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	so := pdu.SuccessfulOutcome
	so.ProcedureCode.Value = ngapType.ProcedureCodeHandoverResourceAllocation
	so.Criticality.Value = ngapType.CriticalityPresentReject
	so.Value.Present = ngapType.SuccessfulOutcomePresentHandoverRequestAcknowledge
	so.Value.HandoverRequestAcknowledge = new(ngapType.HandoverRequestAcknowledge)

	ies := &so.Value.HandoverRequestAcknowledge.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.HandoverRequestAcknowledgeIEsValue {
		ie := ngapType.HandoverRequestAcknowledgeIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)
		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverRequestAcknowledgeIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: p.AMFUENGAPID}

	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverRequestAcknowledgeIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: p.RANUENGAPID}

	admitted := &ngapType.PDUSessionResourceAdmittedList{}
	for _, s := range p.Sessions {
		transfer := s.RawTransfer
		if transfer == nil {
			var err error

			transfer, err = buildHandoverRequestAcknowledgeTransfer(s.DLTeid, s.DLIP)
			if err != nil {
				return nil, err
			}
		}

		admitted.List = append(admitted.List, ngapType.PDUSessionResourceAdmittedItem{
			PDUSessionID:                       ngapType.PDUSessionID{Value: s.PDUSessionID},
			HandoverRequestAcknowledgeTransfer: transfer,
		})
	}

	add(ngapType.ProtocolIEIDPDUSessionResourceAdmittedList, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceAdmittedList).PDUSessionResourceAdmittedList = admitted

	if len(p.Failed) > 0 {
		unsuccessful, err := buildHandoverResourceAllocationUnsuccessfulTransfer()
		if err != nil {
			return nil, err
		}

		failedList := &ngapType.PDUSessionResourceFailedToSetupListHOAck{}
		for _, id := range p.Failed {
			failedList.List = append(failedList.List, ngapType.PDUSessionResourceFailedToSetupItemHOAck{
				PDUSessionID: ngapType.PDUSessionID{Value: id},
				HandoverResourceAllocationUnsuccessfulTransfer: unsuccessful,
			})
		}

		add(ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListHOAck, ngapType.CriticalityPresentIgnore,
			ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceFailedToSetupListHOAck).PDUSessionResourceFailedToSetupListHOAck = failedList
	}

	add(ngapType.ProtocolIEIDTargetToSourceTransparentContainer, ngapType.CriticalityPresentReject,
		ngapType.HandoverRequestAcknowledgeIEsPresentTargetToSourceTransparentContainer).TargetToSourceTransparentContainer =
		&ngapType.TargetToSourceTransparentContainer{Value: []byte{0x00}}

	return ngap.Encoder(pdu)
}

func buildHandoverResourceAllocationUnsuccessfulTransfer() ([]byte, error) {
	transfer := ngapType.HandoverResourceAllocationUnsuccessfulTransfer{
		Cause: ngapType.Cause{
			Present:      ngapType.CausePresentRadioNetwork,
			RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(CauseRadioNetworkRadioResourcesNotAvailable)},
		},
	}

	buf, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal HandoverResourceAllocationUnsuccessfulTransfer: %w", err)
	}

	return buf, nil
}

func buildHandoverRequestAcknowledgeTransfer(teid uint32, ip string) ([]byte, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("parse DL IP %q: %w", ip, err)
	}

	var ipBytes []byte
	if addr.Is4() {
		v4 := addr.As4()
		ipBytes = v4[:]
	} else {
		v6 := addr.As16()
		ipBytes = v6[:]
	}

	teidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(teidBytes, teid)

	transfer := ngapType.HandoverRequestAcknowledgeTransfer{}
	transfer.DLNGUUPTNLInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	transfer.DLNGUUPTNLInformation.GTPTunnel = &ngapType.GTPTunnel{
		TransportLayerAddress: ngapType.TransportLayerAddress{
			Value: aper.BitString{Bytes: ipBytes, BitLength: uint64(len(ipBytes) * 8)},
		},
		GTPTEID: ngapType.GTPTEID{Value: teidBytes},
	}
	transfer.QosFlowSetupResponseList.List = append(transfer.QosFlowSetupResponseList.List,
		ngapType.QosFlowItemWithDataForwarding{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}})

	buf, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal HandoverRequestAcknowledgeTransfer: %w", err)
	}

	return buf, nil
}

func BuildHandoverFailure(amfUeNgapID, causeRadioNetwork int64) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentUnsuccessfulOutcome
	pdu.UnsuccessfulOutcome = new(ngapType.UnsuccessfulOutcome)

	uo := pdu.UnsuccessfulOutcome
	uo.ProcedureCode.Value = ngapType.ProcedureCodeHandoverResourceAllocation
	uo.Criticality.Value = ngapType.CriticalityPresentReject
	uo.Value.Present = ngapType.UnsuccessfulOutcomePresentHandoverFailure
	uo.Value.HandoverFailure = new(ngapType.HandoverFailure)

	ies := &uo.Value.HandoverFailure.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.HandoverFailureIEsValue {
		ie := ngapType.HandoverFailureIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverFailureIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDCause, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverFailureIEsPresentCause).Cause = &ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(causeRadioNetwork)},
	}

	return ngap.Encoder(pdu)
}

func BuildInitialContextSetupFailure(amfUeNgapID, ranUeNgapID, causeRadioNetwork int64) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentUnsuccessfulOutcome
	pdu.UnsuccessfulOutcome = new(ngapType.UnsuccessfulOutcome)

	uo := pdu.UnsuccessfulOutcome
	uo.ProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup
	uo.Criticality.Value = ngapType.CriticalityPresentReject
	uo.Value.Present = ngapType.UnsuccessfulOutcomePresentInitialContextSetupFailure
	uo.Value.InitialContextSetupFailure = new(ngapType.InitialContextSetupFailure)

	ies := &uo.Value.InitialContextSetupFailure.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.InitialContextSetupFailureIEsValue {
		ie := ngapType.InitialContextSetupFailureIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.InitialContextSetupFailureIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.InitialContextSetupFailureIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}
	add(ngapType.ProtocolIEIDCause, ngapType.CriticalityPresentIgnore,
		ngapType.InitialContextSetupFailureIEsPresentCause).Cause = &ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(causeRadioNetwork)},
	}

	return ngap.Encoder(pdu)
}

func BuildHandoverCancel(amfUeNgapID, ranUeNgapID, causeRadioNetwork int64) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeHandoverCancel
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentHandoverCancel
	im.Value.HandoverCancel = new(ngapType.HandoverCancel)

	ies := &im.Value.HandoverCancel.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.HandoverCancelIEsValue {
		ie := ngapType.HandoverCancelIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.HandoverCancelIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.HandoverCancelIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}
	add(ngapType.ProtocolIEIDCause, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverCancelIEsPresentCause).Cause = &ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(causeRadioNetwork)},
	}

	return ngap.Encoder(pdu)
}

type DRBStatusTransferItem struct {
	DRBID    int64
	ULPDCPSN int64
	ULHFN    int64
	DLPDCPSN int64
	DLHFN    int64
}

func BuildUplinkRANStatusTransfer(amfUeNgapID, ranUeNgapID int64, drbs []DRBStatusTransferItem) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeUplinkRANStatusTransfer
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentUplinkRANStatusTransfer
	im.Value.UplinkRANStatusTransfer = new(ngapType.UplinkRANStatusTransfer)

	ies := &im.Value.UplinkRANStatusTransfer.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.UplinkRANStatusTransferIEsValue {
		ie := ngapType.UplinkRANStatusTransferIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.UplinkRANStatusTransferIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}

	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.UplinkRANStatusTransferIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}

	container := new(ngapType.RANStatusTransferTransparentContainer)

	for _, d := range drbs {
		item := ngapType.DRBsSubjectToStatusTransferItem{DRBID: ngapType.DRBID{Value: d.DRBID}}

		item.DRBStatusUL.Present = ngapType.DRBStatusULPresentDRBStatusUL12
		item.DRBStatusUL.DRBStatusUL12 = &ngapType.DRBStatusUL12{
			ULCOUNTValue: ngapType.COUNTValueForPDCPSN12{PDCPSN12: d.ULPDCPSN, HFNPDCPSN12: d.ULHFN},
		}

		item.DRBStatusDL.Present = ngapType.DRBStatusDLPresentDRBStatusDL12
		item.DRBStatusDL.DRBStatusDL12 = &ngapType.DRBStatusDL12{
			DLCOUNTValue: ngapType.COUNTValueForPDCPSN12{PDCPSN12: d.DLPDCPSN, HFNPDCPSN12: d.DLHFN},
		}

		container.DRBsSubjectToStatusTransferList.List = append(container.DRBsSubjectToStatusTransferList.List, item)
	}

	add(ngapType.ProtocolIEIDRANStatusTransferTransparentContainer, ngapType.CriticalityPresentReject,
		ngapType.UplinkRANStatusTransferIEsPresentRANStatusTransferTransparentContainer).RANStatusTransferTransparentContainer = container

	return ngap.Encoder(pdu)
}

type HandoverNotifyParams struct {
	AMFUENGAPID int64
	RANUENGAPID int64
	MCC         string
	MNC         string
	TAC         string
	GNBID       string
}

func BuildHandoverNotify(p HandoverNotifyParams) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeHandoverNotification
	im.Criticality.Value = ngapType.CriticalityPresentIgnore
	im.Value.Present = ngapType.InitiatingMessagePresentHandoverNotify
	im.Value.HandoverNotify = new(ngapType.HandoverNotify)

	ies := &im.Value.HandoverNotify.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.HandoverNotifyIEsValue {
		ie := ngapType.HandoverNotifyIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)
		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.HandoverNotifyIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: p.AMFUENGAPID}

	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.HandoverNotifyIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: p.RANUENGAPID}

	plmnID, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, fmt.Errorf("PLMN: %w", err)
	}

	tacBytes, err := parseTAC(p.TAC)
	if err != nil {
		return nil, fmt.Errorf("TAC: %w", err)
	}

	nrCellID, err := nrCellIdentity(p.GNBID)
	if err != nil {
		return nil, fmt.Errorf("NRCellIdentity: %w", err)
	}

	add(ngapType.ProtocolIEIDUserLocationInformation, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverNotifyIEsPresentUserLocationInformation).UserLocationInformation = &ngapType.UserLocationInformation{
		Present: ngapType.UserLocationInformationPresentUserLocationInformationNR,
		UserLocationInformationNR: &ngapType.UserLocationInformationNR{
			NRCGI: ngapType.NRCGI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmnID}, NRCellIdentity: nrCellID},
			TAI:   ngapType.TAI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmnID}, TAC: ngapType.TAC{Value: tacBytes}},
		},
	}

	return ngap.Encoder(pdu)
}
