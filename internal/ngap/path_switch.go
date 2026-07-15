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

// PathSwitchSession is a PDU session whose downlink GTP-U tunnel a PATH SWITCH
// REQUEST asks the AMF to switch toward the new NG-RAN node (TS 38.413
// §9.2.3.8). RawTransfer, when set, replaces the built Path Switch Request
// Transfer verbatim — for crafting malformed transfers.
type PathSwitchSession struct {
	PDUSessionID int64
	DLTeid       uint32
	DLIP         string
	RawTransfer  []byte
}

// UESecurityCapabilities holds the NR/E-UTRA encryption and integrity algorithm
// bitmaps a PATH SWITCH REQUEST reports for the UE (TS 38.413 §9.3.1.86). Each
// is a 16-bit big-endian bitmap.
type UESecurityCapabilities struct {
	NREncryption    []byte
	NRIntegrity     []byte
	EUTRAEncryption []byte
	EUTRAIntegrity  []byte
}

// BuildPathSwitchRequest builds a PATH SWITCH REQUEST (TS 38.413 §8.4.4) sent by
// an NG-RAN node to switch a UE's downlink user-plane path toward itself.
// sourceAmfUeNgapID identifies the existing UE context; ranUeNgapID is the
// NG-RAN node's newly assigned RAN UE NGAP ID. omitIEs lists protocol IE ids to
// drop from the built message, so a test can send a structurally-incomplete
// request (e.g. missing a mandatory IE) to probe the AMF's error handling; for
// fully arbitrary bytes use the raw_ngap_pdu path instead.
func BuildPathSwitchRequest(ranUeNgapID, sourceAmfUeNgapID int64, mcc, mnc, tac, gnbID string, secCaps UESecurityCapabilities, sessions []PathSwitchSession, failed []int64, omitIEs []int64) ([]byte, error) {
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
		ngapType.PathSwitchRequestIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}

	add(ngapType.ProtocolIEIDSourceAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.PathSwitchRequestIEsPresentSourceAMFUENGAPID).SourceAMFUENGAPID = &ngapType.AMFUENGAPID{Value: sourceAmfUeNgapID}

	plmnID, err := encodePLMN(mcc, mnc)
	if err != nil {
		return nil, fmt.Errorf("PLMN: %w", err)
	}

	tacBytes, err := tacInBytes(tac)
	if err != nil {
		return nil, fmt.Errorf("TAC: %w", err)
	}

	nrCellID, err := nrCellIdentity(gnbID)
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
		NRencryptionAlgorithms:             ngapType.NRencryptionAlgorithms{Value: secBitString(secCaps.NREncryption)},
		NRintegrityProtectionAlgorithms:    ngapType.NRintegrityProtectionAlgorithms{Value: secBitString(secCaps.NRIntegrity)},
		EUTRAencryptionAlgorithms:          ngapType.EUTRAencryptionAlgorithms{Value: secBitString(secCaps.EUTRAEncryption)},
		EUTRAintegrityProtectionAlgorithms: ngapType.EUTRAintegrityProtectionAlgorithms{Value: secBitString(secCaps.EUTRAIntegrity)},
	}

	switchedList := &ngapType.PDUSessionResourceToBeSwitchedDLList{}
	for _, s := range sessions {
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

	if len(failed) > 0 {
		setupFailed, err := buildPathSwitchRequestSetupFailedTransfer()
		if err != nil {
			return nil, err
		}

		failedList := &ngapType.PDUSessionResourceFailedToSetupListPSReq{}
		for _, id := range failed {
			failedList.List = append(failedList.List, ngapType.PDUSessionResourceFailedToSetupItemPSReq{
				PDUSessionID:                         ngapType.PDUSessionID{Value: id},
				PathSwitchRequestSetupFailedTransfer: setupFailed,
			})
		}

		add(ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListPSReq, ngapType.CriticalityPresentIgnore,
			ngapType.PathSwitchRequestIEsPresentPDUSessionResourceFailedToSetupListPSReq).PDUSessionResourceFailedToSetupListPSReq = failedList
	}

	if len(omitIEs) > 0 {
		omit := make(map[int64]bool, len(omitIEs))
		for _, id := range omitIEs {
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

// buildPathSwitchRequestTransfer encodes the per-session Path Switch Request
// Transfer (TS 38.413 §9.3.4.8) carrying the NG-RAN node's downlink GTP-U
// tunnel endpoint and a single accepted QoS flow.
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

// buildPathSwitchRequestSetupFailedTransfer encodes the per-session failure
// transfer carried for each PDU session the NG-RAN node reports as failed to
// set up (TS 38.413 §9.3.4.15).
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
