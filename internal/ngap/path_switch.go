// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type PathSwitchSession struct {
	PDUSessionID int64
	DLTeid       uint32
	DLIP         string
	RawTransfer  []byte
}

// Each bitmap is 16 bits, big-endian (TS 38.413 §9.3.1.86).
type UESecurityCapabilities struct {
	NREncryption    []byte
	NRIntegrity     []byte
	EUTRAEncryption []byte
	EUTRAIntegrity  []byte
}

type PathSwitchRequestParams struct {
	RANUENGAPID       int64
	SourceAMFUENGAPID int64
	MCC               string
	MNC               string
	TAC               string
	GnbID             string
	SecCaps           UESecurityCapabilities
	Sessions          []PathSwitchSession
	Failed            []int64
	OmitIEs           []int64
}

func BuildPathSwitchRequest(p PathSwitchRequestParams) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodePathSwitchRequest
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentPathSwitchRequest
	im.Value.PathSwitchRequest = new(ngapType.PathSwitchRequest)

	ies := &im.Value.PathSwitchRequest.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.PathSwitchRequestIEsValue {
		ie := ngapType.PathSwitchRequestIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)
		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.PathSwitchRequestIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: p.RANUENGAPID}

	add(ngapType.ProtocolIEIDSourceAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.PathSwitchRequestIEsPresentSourceAMFUENGAPID).SourceAMFUENGAPID = &ngapType.AMFUENGAPID{Value: p.SourceAMFUENGAPID}

	plmnID, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, fmt.Errorf("PLMN: %w", err)
	}

	tacBytes, err := tacInBytes(p.TAC)
	if err != nil {
		return nil, fmt.Errorf("TAC: %w", err)
	}

	nrCellID, err := nrCellIdentity(p.GnbID)
	if err != nil {
		return nil, fmt.Errorf("NRCellIdentity: %w", err)
	}

	add(ngapType.ProtocolIEIDUserLocationInformation, ngapType.CriticalityPresentIgnore,
		ngapType.PathSwitchRequestIEsPresentUserLocationInformation).UserLocationInformation = &ngapType.UserLocationInformation{
		Present: ngapType.UserLocationInformationPresentUserLocationInformationNR,
		UserLocationInformationNR: &ngapType.UserLocationInformationNR{
			NRCGI: ngapType.NRCGI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmnID}, NRCellIdentity: nrCellID},
			TAI:   ngapType.TAI{PLMNIdentity: ngapType.PLMNIdentity{Value: plmnID}, TAC: ngapType.TAC{Value: tacBytes}},
		},
	}

	secBitString := func(b []byte) aper.BitString {
		return aper.BitString{Bytes: b, BitLength: uint64(len(b) * 8)}
	}

	add(ngapType.ProtocolIEIDUESecurityCapabilities, ngapType.CriticalityPresentIgnore,
		ngapType.PathSwitchRequestIEsPresentUESecurityCapabilities).UESecurityCapabilities = &ngapType.UESecurityCapabilities{
		NRencryptionAlgorithms:             ngapType.NRencryptionAlgorithms{Value: secBitString(p.SecCaps.NREncryption)},
		NRintegrityProtectionAlgorithms:    ngapType.NRintegrityProtectionAlgorithms{Value: secBitString(p.SecCaps.NRIntegrity)},
		EUTRAencryptionAlgorithms:          ngapType.EUTRAencryptionAlgorithms{Value: secBitString(p.SecCaps.EUTRAEncryption)},
		EUTRAintegrityProtectionAlgorithms: ngapType.EUTRAintegrityProtectionAlgorithms{Value: secBitString(p.SecCaps.EUTRAIntegrity)},
	}

	switchedList := &ngapType.PDUSessionResourceToBeSwitchedDLList{}
	for _, s := range p.Sessions {
		transfer := s.RawTransfer
		if transfer == nil {
			transfer, err = buildPathSwitchRequestTransfer(s.DLTeid, s.DLIP)
			if err != nil {
				return nil, err
			}
		}

		switchedList.List = append(switchedList.List, ngapType.PDUSessionResourceToBeSwitchedDLItem{
			PDUSessionID:              ngapType.PDUSessionID{Value: s.PDUSessionID},
			PathSwitchRequestTransfer: transfer,
		})
	}

	add(ngapType.ProtocolIEIDPDUSessionResourceToBeSwitchedDLList, ngapType.CriticalityPresentReject,
		ngapType.PathSwitchRequestIEsPresentPDUSessionResourceToBeSwitchedDLList).PDUSessionResourceToBeSwitchedDLList = switchedList

	if len(p.Failed) > 0 {
		setupFailed, err := buildPathSwitchRequestSetupFailedTransfer()
		if err != nil {
			return nil, err
		}

		failedList := &ngapType.PDUSessionResourceFailedToSetupListPSReq{}
		for _, id := range p.Failed {
			failedList.List = append(failedList.List, ngapType.PDUSessionResourceFailedToSetupItemPSReq{
				PDUSessionID:                         ngapType.PDUSessionID{Value: id},
				PathSwitchRequestSetupFailedTransfer: setupFailed,
			})
		}

		add(ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListPSReq, ngapType.CriticalityPresentIgnore,
			ngapType.PathSwitchRequestIEsPresentPDUSessionResourceFailedToSetupListPSReq).PDUSessionResourceFailedToSetupListPSReq = failedList
	}

	if len(p.OmitIEs) > 0 {
		omit := make(map[int64]bool, len(p.OmitIEs))
		for _, id := range p.OmitIEs {
			omit[id] = true
		}

		kept := ies.List[:0]
		for _, ie := range ies.List {
			if !omit[ie.Id.Value] {
				kept = append(kept, ie)
			}
		}

		ies.List = kept
	}

	return ngap.Encoder(pdu)
}

func buildPathSwitchRequestTransfer(teid uint32, ip string) ([]byte, error) {
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

	transfer := ngapType.PathSwitchRequestTransfer{}
	transfer.DLNGUUPTNLInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	transfer.DLNGUUPTNLInformation.GTPTunnel = &ngapType.GTPTunnel{
		TransportLayerAddress: ngapType.TransportLayerAddress{
			Value: aper.BitString{Bytes: ipBytes, BitLength: uint64(len(ipBytes) * 8)},
		},
		GTPTEID: ngapType.GTPTEID{Value: teidBytes},
	}
	transfer.QosFlowAcceptedList.List = append(transfer.QosFlowAcceptedList.List,
		ngapType.QosFlowAcceptedItem{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}})

	buf, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal PathSwitchRequestTransfer: %w", err)
	}

	return buf, nil
}

func buildPathSwitchRequestSetupFailedTransfer() ([]byte, error) {
	transfer := ngapType.PathSwitchRequestSetupFailedTransfer{
		Cause: ngapType.Cause{
			Present:      ngapType.CausePresentRadioNetwork,
			RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(CauseRadioNetworkRadioResourcesNotAvailable)},
		},
	}

	buf, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal PathSwitchRequestSetupFailedTransfer: %w", err)
	}

	return buf, nil
}
