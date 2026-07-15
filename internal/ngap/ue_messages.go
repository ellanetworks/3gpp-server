// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func buildInitialUEMessage(msg *NGAPMessage) (ngapType.NGAPPDU, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeInitialUEMessage
	im.Criticality.Value = ngapType.CriticalityPresentIgnore
	im.Value.Present = ngapType.InitiatingMessagePresentInitialUEMessage
	im.Value.InitialUEMessage = new(ngapType.InitialUEMessage)

	ies := &im.Value.InitialUEMessage.ProtocolIEs

	for _, ie := range msg.IEs {
		ngapIE, err := buildInitialUEMessageIE(&ie)
		if err != nil {
			return pdu, fmt.Errorf("IE id=%d: %w", ie.ID, err)
		}
		if ngapIE != nil {
			ies.List = append(ies.List, *ngapIE)
		}
	}

	return pdu, nil
}

func buildInitialUEMessageIE(ie *IE) (*ngapType.InitialUEMessageIEs, error) {
	out := ngapType.InitialUEMessageIEs{}
	out.Id.Value = ie.ID
	out.Criticality.Value = parseCriticality(ie.Criticality)

	switch ie.ID {
	case ngapType.ProtocolIEIDRANUENGAPID:
		if ie.RanUeNgapID == nil {
			return nil, fmt.Errorf("ran_ue_ngap_id is required")
		}
		out.Value.Present = ngapType.InitialUEMessageIEsPresentRANUENGAPID
		out.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
		out.Value.RANUENGAPID.Value = *ie.RanUeNgapID

	case ngapType.ProtocolIEIDNASPDU:
		if ie.NasPDU == nil {
			return nil, fmt.Errorf("nas_pdu is required")
		}
		nasPDU, err := hex.DecodeString(*ie.NasPDU)
		if err != nil {
			return nil, fmt.Errorf("decode nas_pdu hex: %w", err)
		}
		out.Value.Present = ngapType.InitialUEMessageIEsPresentNASPDU
		out.Value.NASPDU = new(ngapType.NASPDU)
		out.Value.NASPDU.Value = nasPDU

	case ngapType.ProtocolIEIDUserLocationInformation:
		if ie.UserLocationInformation == nil {
			return nil, fmt.Errorf("user_location_information is required")
		}
		out.Value.Present = ngapType.InitialUEMessageIEsPresentUserLocationInformation
		out.Value.UserLocationInformation = new(ngapType.UserLocationInformation)

		uli := out.Value.UserLocationInformation
		uli.Present = ngapType.UserLocationInformationPresentUserLocationInformationNR
		uli.UserLocationInformationNR = new(ngapType.UserLocationInformationNR)

		nr := uli.UserLocationInformationNR
		if ie.UserLocationInformation.NR != nil {
			plmnBytes, err := hex.DecodeString(ie.UserLocationInformation.NR.NRCGI.PLMNIdentity)
			if err != nil {
				return nil, fmt.Errorf("decode nrcgi plmn: %w", err)
			}
			nr.NRCGI.PLMNIdentity.Value = plmnBytes

			nrCellID, err := nrCellIdentity(ie.UserLocationInformation.NR.NRCGI.NRCellIdentity)
			if err != nil {
				return nil, fmt.Errorf("decode nr_cell_identity: %w", err)
			}
			nr.NRCGI.NRCellIdentity = nrCellID

			taiPlmn, err := hex.DecodeString(ie.UserLocationInformation.NR.TAI.PLMNIdentity)
			if err != nil {
				return nil, fmt.Errorf("decode tai plmn: %w", err)
			}
			nr.TAI.PLMNIdentity.Value = taiPlmn

			tac, err := tacInBytes(ie.UserLocationInformation.NR.TAI.TAC)
			if err != nil {
				return nil, fmt.Errorf("decode tai tac: %w", err)
			}
			nr.TAI.TAC.Value = tac
		}

	case ngapType.ProtocolIEIDRRCEstablishmentCause:
		out.Value.Present = ngapType.InitialUEMessageIEsPresentRRCEstablishmentCause
		out.Value.RRCEstablishmentCause = new(ngapType.RRCEstablishmentCause)
		if ie.RRCEstablishmentCause != nil {
			out.Value.RRCEstablishmentCause.Value = aper.Enumerated(*ie.RRCEstablishmentCause)
		} else {
			out.Value.RRCEstablishmentCause.Value = ngapType.RRCEstablishmentCausePresentMoSignalling
		}

	case ngapType.ProtocolIEIDFiveGSTMSI:
		if ie.FiveGSTMSI == nil {
			return nil, fmt.Errorf("five_g_s_tmsi is required")
		}
		out.Value.Present = ngapType.InitialUEMessageIEsPresentFiveGSTMSI
		out.Value.FiveGSTMSI = new(ngapType.FiveGSTMSI)

		amfSetIDBytes, err := hex.DecodeString(ie.FiveGSTMSI.AMFSetID)
		if err != nil {
			return nil, fmt.Errorf("decode amf_set_id: %w", err)
		}
		out.Value.FiveGSTMSI.AMFSetID.Value = aper.BitString{
			Bytes:     amfSetIDBytes,
			BitLength: 10,
		}

		amfPointerBytes, err := hex.DecodeString(ie.FiveGSTMSI.AMFPointer)
		if err != nil {
			return nil, fmt.Errorf("decode amf_pointer: %w", err)
		}
		out.Value.FiveGSTMSI.AMFPointer.Value = aper.BitString{
			Bytes:     amfPointerBytes,
			BitLength: 6,
		}

		tmsiBytes, err := hex.DecodeString(ie.FiveGSTMSI.FiveGTMSI)
		if err != nil {
			return nil, fmt.Errorf("decode five_g_tmsi: %w", err)
		}
		out.Value.FiveGSTMSI.FiveGTMSI.Value = tmsiBytes

	case ngapType.ProtocolIEIDUEContextRequest:
		out.Value.Present = ngapType.InitialUEMessageIEsPresentUEContextRequest
		out.Value.UEContextRequest = new(ngapType.UEContextRequest)
		if ie.UEContextRequest != nil {
			out.Value.UEContextRequest.Value = aper.Enumerated(*ie.UEContextRequest)
		} else {
			out.Value.UEContextRequest.Value = ngapType.UEContextRequestPresentRequested
		}

	case ngapType.ProtocolIEIDAMFSetID:
		if ie.AMFSetID == nil {
			return nil, fmt.Errorf("amf_set_id_ie is required")
		}
		amfSetIDBytes, err := hex.DecodeString(*ie.AMFSetID)
		if err != nil {
			return nil, fmt.Errorf("decode amf_set_id: %w", err)
		}
		out.Value.Present = ngapType.InitialUEMessageIEsPresentAMFSetID
		out.Value.AMFSetID = new(ngapType.AMFSetID)
		out.Value.AMFSetID.Value = aper.BitString{
			Bytes:     amfSetIDBytes,
			BitLength: 10,
		}

	case ngapType.ProtocolIEIDAllowedNSSAI:
		if ie.AllowedNSSAI == nil {
			return nil, fmt.Errorf("allowed_nssai is required")
		}
		out.Value.Present = ngapType.InitialUEMessageIEsPresentAllowedNSSAI
		out.Value.AllowedNSSAI = new(ngapType.AllowedNSSAI)
		for _, item := range ie.AllowedNSSAI {
			nssaiItem := ngapType.AllowedNSSAIItem{}
			sstBytes, err := hex.DecodeString(item.SST)
			if err != nil {
				return nil, fmt.Errorf("decode allowed_nssai sst: %w", err)
			}
			nssaiItem.SNSSAI.SST.Value = sstBytes
			if item.SD != "" {
				sdBytes, err := hex.DecodeString(item.SD)
				if err != nil {
					return nil, fmt.Errorf("decode allowed_nssai sd: %w", err)
				}
				nssaiItem.SNSSAI.SD = new(ngapType.SD)
				nssaiItem.SNSSAI.SD.Value = sdBytes
			}
			out.Value.AllowedNSSAI.List = append(out.Value.AllowedNSSAI.List, nssaiItem)
		}

	default:
		return nil, fmt.Errorf("unsupported InitialUEMessage IE id: %d", ie.ID)
	}

	return &out, nil
}

// BuildInitialUEMessageFromState creates the NGAP InitialUEMessage using gNB and UE state.
type InitialUEMessageOverrides struct {
	RRCEstablishmentCause *int64
	UEContextRequest      *int64
	RanUeNgapID           *int64
}

func BuildInitialUEMessageFromState(ranUeNgapID int64, nasPDU []byte, mcc, mnc, tac, gnbID string, guti *FiveGSTMSIFromGUTI, overrides *InitialUEMessageOverrides) (*NGAPMessage, error) {
	plmnID, err := encodePLMN(mcc, mnc)
	if err != nil {
		return nil, fmt.Errorf("PLMN: %w", err)
	}

	plmnHex := hex.EncodeToString(plmnID)
	nasPDUHex := hex.EncodeToString(nasPDU)

	effectiveRanID := ranUeNgapID
	if overrides != nil && overrides.RanUeNgapID != nil {
		effectiveRanID = *overrides.RanUeNgapID
	}

	rrcCause := int64(ngapType.RRCEstablishmentCausePresentMoSignalling)
	if overrides != nil && overrides.RRCEstablishmentCause != nil {
		rrcCause = *overrides.RRCEstablishmentCause
	}

	ies := []IE{
		{
			ID:          ngapType.ProtocolIEIDRANUENGAPID,
			Criticality: "reject",
			RanUeNgapID: &effectiveRanID,
		},
		{
			ID:          ngapType.ProtocolIEIDNASPDU,
			Criticality: "reject",
			NasPDU:      &nasPDUHex,
		},
		{
			ID:          ngapType.ProtocolIEIDUserLocationInformation,
			Criticality: "reject",
			UserLocationInformation: &UserLocationInformationJSON{
				Present: "nr",
				NR: &UserLocationInformationNRJSON{
					NRCGI: NRCGIJSON{
						PLMNIdentity:   plmnHex,
						NRCellIdentity: gnbID,
					},
					TAI: TAIJSON{
						PLMNIdentity: plmnHex,
						TAC:          tac,
					},
				},
			},
		},
		{
			ID:                    ngapType.ProtocolIEIDRRCEstablishmentCause,
			Criticality:           "ignore",
			RRCEstablishmentCause: &rrcCause,
		},
	}

	if guti != nil {
		ies = append(ies, IE{
			ID:          ngapType.ProtocolIEIDFiveGSTMSI,
			Criticality: "reject",
			FiveGSTMSI: &FiveGSTMSIJSON{
				AMFSetID:   guti.AMFSetID,
				AMFPointer: guti.AMFPointer,
				FiveGTMSI:  guti.FiveGTMSI,
			},
		})
	}

	if overrides == nil || overrides.UEContextRequest == nil || *overrides.UEContextRequest >= 0 {
		ueContextReq := int64(ngapType.UEContextRequestPresentRequested)
		if overrides != nil && overrides.UEContextRequest != nil {
			ueContextReq = *overrides.UEContextRequest
		}

		ies = append(ies, IE{
			ID:               ngapType.ProtocolIEIDUEContextRequest,
			Criticality:      "ignore",
			UEContextRequest: &ueContextReq,
		})
	}

	return &NGAPMessage{
		ProcedureCode: ngapType.ProcedureCodeInitialUEMessage,
		PDUType:       "initiating_message",
		Criticality:   "ignore",
		IEs:           ies,
	}, nil
}

type FiveGSTMSIFromGUTI struct {
	AMFSetID   string
	AMFPointer string
	FiveGTMSI  string
}

type UplinkNASTransportOverrides struct {
	AmfUeNgapID *int64
	RanUeNgapID *int64
}

func BuildUplinkNASTransport(amfUeNgapID, ranUeNgapID int64, nasPDU []byte, mcc, mnc, tac, gnbID string, overrides *UplinkNASTransportOverrides) ([]byte, error) {
	if overrides != nil && overrides.AmfUeNgapID != nil {
		amfUeNgapID = *overrides.AmfUeNgapID
	}

	if overrides != nil && overrides.RanUeNgapID != nil {
		ranUeNgapID = *overrides.RanUeNgapID
	}
	plmnBytes, err := encodePLMN(mcc, mnc)
	if err != nil {
		return nil, fmt.Errorf("PLMN: %w", err)
	}

	plmnID := ngapType.PLMNIdentity{Value: plmnBytes}

	nrCellID, err := nrCellIdentity(gnbID)
	if err != nil {
		return nil, fmt.Errorf("NRCellIdentity: %w", err)
	}

	tacBytes, err := tacInBytes(tac)
	if err != nil {
		return nil, fmt.Errorf("TAC: %w", err)
	}

	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeUplinkNASTransport
	im.Criticality.Value = ngapType.CriticalityPresentIgnore
	im.Value.Present = ngapType.InitiatingMessagePresentUplinkNASTransport
	im.Value.UplinkNASTransport = new(ngapType.UplinkNASTransport)

	ies := &im.Value.UplinkNASTransport.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.UplinkNASTransportIEsValue {
		ie := ngapType.UplinkNASTransportIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.UplinkNASTransportIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.UplinkNASTransportIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}
	add(ngapType.ProtocolIEIDNASPDU, ngapType.CriticalityPresentReject,
		ngapType.UplinkNASTransportIEsPresentNASPDU).NASPDU = &ngapType.NASPDU{Value: nasPDU}
	add(ngapType.ProtocolIEIDUserLocationInformation, ngapType.CriticalityPresentIgnore,
		ngapType.UplinkNASTransportIEsPresentUserLocationInformation).UserLocationInformation = &ngapType.UserLocationInformation{
		Present: ngapType.UserLocationInformationPresentUserLocationInformationNR,
		UserLocationInformationNR: &ngapType.UserLocationInformationNR{
			NRCGI: ngapType.NRCGI{PLMNIdentity: plmnID, NRCellIdentity: nrCellID},
			TAI:   ngapType.TAI{PLMNIdentity: plmnID, TAC: ngapType.TAC{Value: tacBytes}},
		},
	}

	return ngap.Encoder(pdu)
}

// buildPDUSessionResourceSetupResponseTransfer encodes the gNB's downlink GTP
// tunnel for an admitted PDU session (TS 38.413 §9.3.4.10), reported in the
// PDU Session Resource Setup Response.
func buildPDUSessionResourceSetupResponseTransfer(teid uint32, ip string) ([]byte, error) {
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

	transfer := ngapType.PDUSessionResourceSetupResponseTransfer{}
	qos := &transfer.DLQosFlowPerTNLInformation
	qos.UPTransportLayerInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	qos.UPTransportLayerInformation.GTPTunnel = &ngapType.GTPTunnel{
		TransportLayerAddress: ngapType.TransportLayerAddress{
			Value: aper.BitString{Bytes: ipBytes, BitLength: uint64(len(ipBytes) * 8)},
		},
		GTPTEID: ngapType.GTPTEID{Value: teidBytes},
	}
	qos.AssociatedQosFlowList.List = append(qos.AssociatedQosFlowList.List,
		ngapType.AssociatedQosFlowItem{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}})

	buf, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal PDUSessionResourceSetupResponseTransfer: %w", err)
	}

	return buf, nil
}

func BuildPDUSessionResourceSetupResponse(amfUeNgapID, ranUeNgapID, pduSessionID int64, dlTeid uint32, dlIP string) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	so := pdu.SuccessfulOutcome
	so.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceSetup
	so.Criticality.Value = ngapType.CriticalityPresentReject
	so.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceSetupResponse
	so.Value.PDUSessionResourceSetupResponse = new(ngapType.PDUSessionResourceSetupResponse)

	ies := &so.Value.PDUSessionResourceSetupResponse.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.PDUSessionResourceSetupResponseIEsValue {
		ie := ngapType.PDUSessionResourceSetupResponseIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.PDUSessionResourceSetupResponseIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.PDUSessionResourceSetupResponseIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}

	// Downlink GTP tunnel for the admitted PDU session (TS 38.413 §9.2.1.2).
	transfer, err := buildPDUSessionResourceSetupResponseTransfer(dlTeid, dlIP)
	if err != nil {
		return nil, err
	}

	setupList := &ngapType.PDUSessionResourceSetupListSURes{}
	setupList.List = append(setupList.List, ngapType.PDUSessionResourceSetupItemSURes{
		PDUSessionID:                            ngapType.PDUSessionID{Value: pduSessionID},
		PDUSessionResourceSetupResponseTransfer: transfer,
	})

	add(ngapType.ProtocolIEIDPDUSessionResourceSetupListSURes, ngapType.CriticalityPresentIgnore,
		ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceSetupListSURes).PDUSessionResourceSetupListSURes = setupList

	return ngap.Encoder(pdu)
}

// BuildUERadioCapabilityInfoIndication builds a UE RADIO CAPABILITY INFO
// INDICATION (TS 38.413 §8.14.1); the AMF stores the capability and replays it
// in a later Initial Context Setup Request.
func BuildUERadioCapabilityInfoIndication(amfUeNgapID, ranUeNgapID int64, radioCapability []byte) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeUERadioCapabilityInfoIndication
	im.Criticality.Value = ngapType.CriticalityPresentIgnore
	im.Value.Present = ngapType.InitiatingMessagePresentUERadioCapabilityInfoIndication
	im.Value.UERadioCapabilityInfoIndication = new(ngapType.UERadioCapabilityInfoIndication)

	ies := &im.Value.UERadioCapabilityInfoIndication.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.UERadioCapabilityInfoIndicationIEsValue {
		ie := ngapType.UERadioCapabilityInfoIndicationIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.UERadioCapabilityInfoIndicationIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.UERadioCapabilityInfoIndicationIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}
	add(ngapType.ProtocolIEIDUERadioCapability, ngapType.CriticalityPresentIgnore,
		ngapType.UERadioCapabilityInfoIndicationIEsPresentUERadioCapability).UERadioCapability = &ngapType.UERadioCapability{Value: radioCapability}

	return ngap.Encoder(pdu)
}

// BuildErrorIndication builds an ERROR INDICATION (TS 38.413 §8.7.5) reporting a
// protocol error for the UE-associated connection. The Cause is a radio-network
// value (TS 38.413 §9.3.1.2).
func BuildErrorIndication(amfUeNgapID, ranUeNgapID, causeRadioNetwork int64) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeErrorIndication
	im.Criticality.Value = ngapType.CriticalityPresentIgnore
	im.Value.Present = ngapType.InitiatingMessagePresentErrorIndication
	im.Value.ErrorIndication = new(ngapType.ErrorIndication)

	ies := &im.Value.ErrorIndication.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.ErrorIndicationIEsValue {
		ie := ngapType.ErrorIndicationIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.ErrorIndicationIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.ErrorIndicationIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}
	add(ngapType.ProtocolIEIDCause, ngapType.CriticalityPresentIgnore,
		ngapType.ErrorIndicationIEsPresentCause).Cause = &ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(causeRadioNetwork)},
	}

	return ngap.Encoder(pdu)
}

func BuildPDUSessionResourceReleaseResponse(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	so := pdu.SuccessfulOutcome
	so.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceRelease
	so.Criticality.Value = ngapType.CriticalityPresentReject
	so.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceReleaseResponse
	so.Value.PDUSessionResourceReleaseResponse = new(ngapType.PDUSessionResourceReleaseResponse)

	ies := &so.Value.PDUSessionResourceReleaseResponse.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.PDUSessionResourceReleaseResponseIEsValue {
		ie := ngapType.PDUSessionResourceReleaseResponseIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.PDUSessionResourceReleaseResponseIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.PDUSessionResourceReleaseResponseIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}

	return ngap.Encoder(pdu)
}

func BuildInitialContextSetupResponse(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	so := pdu.SuccessfulOutcome
	so.ProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup
	so.Criticality.Value = ngapType.CriticalityPresentReject
	so.Value.Present = ngapType.SuccessfulOutcomePresentInitialContextSetupResponse
	so.Value.InitialContextSetupResponse = new(ngapType.InitialContextSetupResponse)

	ies := &so.Value.InitialContextSetupResponse.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.InitialContextSetupResponseIEsValue {
		ie := ngapType.InitialContextSetupResponseIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.InitialContextSetupResponseIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.InitialContextSetupResponseIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}

	return ngap.Encoder(pdu)
}

func BuildUEContextReleaseComplete(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	so := pdu.SuccessfulOutcome
	so.ProcedureCode.Value = ngapType.ProcedureCodeUEContextRelease
	so.Criticality.Value = ngapType.CriticalityPresentReject
	so.Value.Present = ngapType.SuccessfulOutcomePresentUEContextReleaseComplete
	so.Value.UEContextReleaseComplete = new(ngapType.UEContextReleaseComplete)

	ies := &so.Value.UEContextReleaseComplete.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.UEContextReleaseCompleteIEsValue {
		ie := ngapType.UEContextReleaseCompleteIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.UEContextReleaseCompleteIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.UEContextReleaseCompleteIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}

	return ngap.Encoder(pdu)
}

// BuildUEContextReleaseRequest builds a gNB-initiated UE CONTEXT RELEASE REQUEST
// (TS 38.413 §8.3.2). It carries the AMF/RAN UE NGAP IDs and a radio-network
// cause. The AMF answers with a UE CONTEXT RELEASE COMMAND.
func BuildUEContextReleaseRequest(amfUeNgapID, ranUeNgapID int64, causeRadioNetwork int64) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeUEContextReleaseRequest
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentUEContextReleaseRequest
	im.Value.UEContextReleaseRequest = new(ngapType.UEContextReleaseRequest)

	ies := &im.Value.UEContextReleaseRequest.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.UEContextReleaseRequestIEsValue {
		ie := ngapType.UEContextReleaseRequestIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDAMFUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.UEContextReleaseRequestIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.UEContextReleaseRequestIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}
	add(ngapType.ProtocolIEIDCause, ngapType.CriticalityPresentIgnore,
		ngapType.UEContextReleaseRequestIEsPresentCause).Cause = &ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(causeRadioNetwork)},
	}

	return ngap.Encoder(pdu)
}
