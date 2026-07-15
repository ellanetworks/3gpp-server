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
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

func Encode(msg *NGAPMessage) ([]byte, error) {
	if msg.RawPDU != "" {
		return hex.DecodeString(msg.RawPDU)
	}

	pdu, err := buildPDU(msg)
	if err != nil {
		return nil, err
	}

	return ngap.Encoder(pdu)
}

func buildPDU(msg *NGAPMessage) (ngapType.NGAPPDU, error) {
	switch msg.ProcedureCode {
	case ngapType.ProcedureCodeNGSetup:
		return buildNGSetupRequest(msg)
	case ngapType.ProcedureCodeInitialUEMessage:
		return buildInitialUEMessage(msg)
	default:
		return ngapType.NGAPPDU{}, fmt.Errorf("unsupported procedure code: %d", msg.ProcedureCode)
	}
}

func buildNGSetupRequest(msg *NGAPMessage) (ngapType.NGAPPDU, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeNGSetup
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentNGSetupRequest
	im.Value.NGSetupRequest = new(ngapType.NGSetupRequest)

	ies := &im.Value.NGSetupRequest.ProtocolIEs

	for _, ie := range msg.IEs {
		ngapIE, err := buildNGSetupRequestIE(&ie)
		if err != nil {
			return pdu, fmt.Errorf("IE id=%d: %w", ie.ID, err)
		}
		if ngapIE != nil {
			ies.List = append(ies.List, *ngapIE)
		}
	}

	return pdu, nil
}

func buildNGSetupRequestIE(ie *IE) (*ngapType.NGSetupRequestIEs, error) {
	out := ngapType.NGSetupRequestIEs{}
	out.Id.Value = ie.ID
	out.Criticality.Value = parseCriticality(ie.Criticality)

	switch ie.ID {
	case ngapType.ProtocolIEIDGlobalRANNodeID:
		if ie.GlobalRANNodeID == nil {
			return nil, fmt.Errorf("global_ran_node_id is required for IE %d", ie.ID)
		}
		out.Value.Present = ngapType.NGSetupRequestIEsPresentGlobalRANNodeID
		out.Value.GlobalRANNodeID = new(ngapType.GlobalRANNodeID)

		g := out.Value.GlobalRANNodeID
		g.Present = ngapType.GlobalRANNodeIDPresentGlobalGNBID
		g.GlobalGNBID = new(ngapType.GlobalGNBID)

		gnbIDData := ie.GlobalRANNodeID.GlobalGNBID
		if gnbIDData == nil {
			return nil, fmt.Errorf("global_gnb_id is required")
		}

		plmnBytes, err := hex.DecodeString(gnbIDData.PLMNIdentity)
		if err != nil {
			return nil, fmt.Errorf("decode plmn_identity: %w", err)
		}
		g.GlobalGNBID.PLMNIdentity.Value = plmnBytes

		g.GlobalGNBID.GNBID.Present = ngapType.GNBIDPresentGNBID
		g.GlobalGNBID.GNBID.GNBID = new(aper.BitString)

		bitLen := gnbIDData.GnbIDBitLen
		if bitLen == 0 {
			bitLen = 24
		}
		*g.GlobalGNBID.GNBID.GNBID = ngapConvert.HexToBitString(gnbIDData.GnbID, bitLen)

	case ngapType.ProtocolIEIDRANNodeName:
		if ie.RANNodeName == nil {
			return nil, fmt.Errorf("ran_node_name is required for IE %d", ie.ID)
		}
		out.Value.Present = ngapType.NGSetupRequestIEsPresentRANNodeName
		out.Value.RANNodeName = new(ngapType.RANNodeName)
		out.Value.RANNodeName.Value = *ie.RANNodeName

	case ngapType.ProtocolIEIDSupportedTAList:
		if ie.SupportedTAList == nil {
			return nil, fmt.Errorf("supported_ta_list is required for IE %d", ie.ID)
		}
		out.Value.Present = ngapType.NGSetupRequestIEsPresentSupportedTAList
		out.Value.SupportedTAList = new(ngapType.SupportedTAList)

		for _, taItem := range ie.SupportedTAList.Items {
			ngapTAItem := ngapType.SupportedTAItem{}

			tacBytes, err := hex.DecodeString(taItem.TAC)
			if err != nil {
				return nil, fmt.Errorf("decode tac: %w", err)
			}
			ngapTAItem.TAC.Value = tacBytes

			for _, bplmn := range taItem.BroadcastPLMNs {
				bplmnItem := ngapType.BroadcastPLMNItem{}

				plmnBytes, err := hex.DecodeString(bplmn.PLMNIdentity)
				if err != nil {
					return nil, fmt.Errorf("decode broadcast plmn: %w", err)
				}
				bplmnItem.PLMNIdentity.Value = plmnBytes

				for _, s := range bplmn.SliceSupport {
					sliceItem := ngapType.SliceSupportItem{}

					sstBytes, err := hex.DecodeString(s.SST)
					if err != nil {
						return nil, fmt.Errorf("decode sst: %w", err)
					}
					sliceItem.SNSSAI.SST.Value = sstBytes

					if s.SD != "" {
						sdBytes, err := hex.DecodeString(s.SD)
						if err != nil {
							return nil, fmt.Errorf("decode sd: %w", err)
						}
						sliceItem.SNSSAI.SD = new(ngapType.SD)
						sliceItem.SNSSAI.SD.Value = sdBytes
					}

					bplmnItem.TAISliceSupportList.List = append(bplmnItem.TAISliceSupportList.List, sliceItem)
				}

				ngapTAItem.BroadcastPLMNList.List = append(ngapTAItem.BroadcastPLMNList.List, bplmnItem)
			}

			out.Value.SupportedTAList.List = append(out.Value.SupportedTAList.List, ngapTAItem)
		}

	case ngapType.ProtocolIEIDDefaultPagingDRX:
		out.Value.Present = ngapType.NGSetupRequestIEsPresentDefaultPagingDRX
		out.Value.DefaultPagingDRX = new(ngapType.PagingDRX)
		if ie.DefaultPagingDRX != nil {
			out.Value.DefaultPagingDRX.Value = aper.Enumerated(*ie.DefaultPagingDRX)
		} else {
			out.Value.DefaultPagingDRX.Value = ngapType.PagingDRXPresentV128
		}

	case ngapType.ProtocolIEIDUERetentionInformation:
		out.Value.Present = ngapType.NGSetupRequestIEsPresentUERetentionInformation
		out.Value.UERetentionInformation = new(ngapType.UERetentionInformation)
		if ie.UERetentionInformation != nil {
			out.Value.UERetentionInformation.Value = aper.Enumerated(*ie.UERetentionInformation)
		}

	default:
		return nil, fmt.Errorf("unsupported NGSetupRequest IE id: %d", ie.ID)
	}

	return &out, nil
}

func parseCriticality(s string) aper.Enumerated {
	switch s {
	case "reject":
		return ngapType.CriticalityPresentReject
	case "ignore":
		return ngapType.CriticalityPresentIgnore
	case "notify":
		return ngapType.CriticalityPresentNotify
	default:
		return ngapType.CriticalityPresentIgnore
	}
}

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

			nrCellID, err := GetNRCellIdentity(ie.UserLocationInformation.NR.NRCGI.NRCellIdentity)
			if err != nil {
				return nil, fmt.Errorf("decode nr_cell_identity: %w", err)
			}
			nr.NRCGI.NRCellIdentity = nrCellID

			taiPlmn, err := hex.DecodeString(ie.UserLocationInformation.NR.TAI.PLMNIdentity)
			if err != nil {
				return nil, fmt.Errorf("decode tai plmn: %w", err)
			}
			nr.TAI.PLMNIdentity.Value = taiPlmn

			tac, err := GetTacInBytes(ie.UserLocationInformation.NR.TAI.TAC)
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

// BuildNGSetupRequestFromStore builds the IE-level NGAPMessage for an
// NGSetupRequest using stored gNB context values. This is the convenience
// path — the caller can override any IE afterward.
func BuildNGSetupRequestFromStore(mcc, mnc, tac, gnbID, name string, sst int32, sd string, slices []struct {
	SST int32
	SD  string
}) (*NGAPMessage, error) {
	plmnID, err := encodePLMN(mcc, mnc)
	if err != nil {
		return nil, fmt.Errorf("PLMN: %w", err)
	}

	plmnHex := hex.EncodeToString(plmnID)

	sliceSupport := make([]SliceSupportJSON, 0)
	if len(slices) > 0 {
		for _, s := range slices {
			ss := SliceSupportJSON{SST: fmt.Sprintf("%02x", byte(s.SST))}
			if s.SD != "" {
				ss.SD = s.SD
			}
			sliceSupport = append(sliceSupport, ss)
		}
	} else {
		ss := SliceSupportJSON{SST: fmt.Sprintf("%02x", byte(sst))}
		if sd != "" {
			ss.SD = sd
		}
		sliceSupport = append(sliceSupport, ss)
	}

	pagingDRX := int64(ngapType.PagingDRXPresentV128)
	nodeName := name

	return &NGAPMessage{
		ProcedureCode: ngapType.ProcedureCodeNGSetup,
		PDUType:       "initiating_message",
		Criticality:   "reject",
		IEs: []IE{
			{
				ID:          ngapType.ProtocolIEIDGlobalRANNodeID,
				Criticality: "reject",
				GlobalRANNodeID: &GlobalRANNodeIDJSON{
					Present: "global_gnb_id",
					GlobalGNBID: &GlobalGNBIDJSON{
						PLMNIdentity: plmnHex,
						GnbID:        gnbID,
						GnbIDBitLen:  24,
					},
				},
			},
			{
				ID:          ngapType.ProtocolIEIDRANNodeName,
				Criticality: "ignore",
				RANNodeName: &nodeName,
			},
			{
				ID:          ngapType.ProtocolIEIDSupportedTAList,
				Criticality: "reject",
				SupportedTAList: &SupportedTAListJSON{
					Items: []SupportedTAItemJSON{
						{
							TAC: tac,
							BroadcastPLMNs: []BroadcastPLMNItemJSON{
								{
									PLMNIdentity: plmnHex,
									SliceSupport: sliceSupport,
								},
							},
						},
					},
				},
			},
			{
				ID:               ngapType.ProtocolIEIDDefaultPagingDRX,
				Criticality:      "ignore",
				DefaultPagingDRX: &pagingDRX,
			},
		},
	}, nil
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

	nrCellID, err := GetNRCellIdentity(gnbID)
	if err != nil {
		return nil, fmt.Errorf("NRCellIdentity: %w", err)
	}

	tacBytes, err := GetTacInBytes(tac)
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

	amfIE := ngapType.UplinkNASTransportIEs{}
	amfIE.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amfIE.Criticality.Value = ngapType.CriticalityPresentReject
	amfIE.Value.Present = ngapType.UplinkNASTransportIEsPresentAMFUENGAPID
	amfIE.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	amfIE.Value.AMFUENGAPID.Value = amfUeNgapID
	ies.List = append(ies.List, amfIE)

	ranIE := ngapType.UplinkNASTransportIEs{}
	ranIE.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ranIE.Criticality.Value = ngapType.CriticalityPresentReject
	ranIE.Value.Present = ngapType.UplinkNASTransportIEsPresentRANUENGAPID
	ranIE.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ranIE.Value.RANUENGAPID.Value = ranUeNgapID
	ies.List = append(ies.List, ranIE)

	nasIE := ngapType.UplinkNASTransportIEs{}
	nasIE.Id.Value = ngapType.ProtocolIEIDNASPDU
	nasIE.Criticality.Value = ngapType.CriticalityPresentReject
	nasIE.Value.Present = ngapType.UplinkNASTransportIEsPresentNASPDU
	nasIE.Value.NASPDU = new(ngapType.NASPDU)
	nasIE.Value.NASPDU.Value = nasPDU
	ies.List = append(ies.List, nasIE)

	uliIE := ngapType.UplinkNASTransportIEs{}
	uliIE.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	uliIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	uliIE.Value.Present = ngapType.UplinkNASTransportIEsPresentUserLocationInformation
	uliIE.Value.UserLocationInformation = new(ngapType.UserLocationInformation)

	uli := uliIE.Value.UserLocationInformation
	uli.Present = ngapType.UserLocationInformationPresentUserLocationInformationNR
	uli.UserLocationInformationNR = new(ngapType.UserLocationInformationNR)
	uli.UserLocationInformationNR.NRCGI.PLMNIdentity = plmnID
	uli.UserLocationInformationNR.NRCGI.NRCellIdentity = nrCellID
	uli.UserLocationInformationNR.TAI.PLMNIdentity = plmnID
	uli.UserLocationInformationNR.TAI.TAC.Value = tacBytes
	ies.List = append(ies.List, uliIE)

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

	amfIE := ngapType.PDUSessionResourceSetupResponseIEs{}
	amfIE.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amfIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	amfIE.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentAMFUENGAPID
	amfIE.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	amfIE.Value.AMFUENGAPID.Value = amfUeNgapID
	ies.List = append(ies.List, amfIE)

	ranIE := ngapType.PDUSessionResourceSetupResponseIEs{}
	ranIE.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ranIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	ranIE.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentRANUENGAPID
	ranIE.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ranIE.Value.RANUENGAPID.Value = ranUeNgapID
	ies.List = append(ies.List, ranIE)

	// Downlink GTP tunnel for the admitted PDU session (TS 38.413 §9.2.1.2).
	transfer, err := buildPDUSessionResourceSetupResponseTransfer(dlTeid, dlIP)
	if err != nil {
		return nil, err
	}

	suIE := ngapType.PDUSessionResourceSetupResponseIEs{}
	suIE.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceSetupListSURes
	suIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	suIE.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentPDUSessionResourceSetupListSURes
	suIE.Value.PDUSessionResourceSetupListSURes = new(ngapType.PDUSessionResourceSetupListSURes)
	suIE.Value.PDUSessionResourceSetupListSURes.List = append(
		suIE.Value.PDUSessionResourceSetupListSURes.List,
		ngapType.PDUSessionResourceSetupItemSURes{
			PDUSessionID:                            ngapType.PDUSessionID{Value: pduSessionID},
			PDUSessionResourceSetupResponseTransfer: transfer,
		},
	)
	ies.List = append(ies.List, suIE)

	return ngap.Encoder(pdu)
}

// NGResetConnection identifies a UE-associated logical NG-connection to reset
// (TS 38.413 §9.2.6.6). At least one of the AMF/RAN UE NGAP IDs is set.
type NGResetConnection struct {
	AmfUeNgapID *int64
	RanUeNgapID *int64
}

// BuildNGReset builds an NG RESET (TS 38.413 §8.7.4) initiated by the NG-RAN
// node. With no connections it resets the whole NG interface; otherwise it
// resets the listed UE-associated logical NG-connections (partOfNG-Interface).
func BuildNGReset(connections []NGResetConnection) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeNGReset
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentNGReset
	im.Value.NGReset = new(ngapType.NGReset)

	ies := &im.Value.NGReset.ProtocolIEs

	causeIE := ngapType.NGResetIEs{}
	causeIE.Id.Value = ngapType.ProtocolIEIDCause
	causeIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	causeIE.Value.Present = ngapType.NGResetIEsPresentCause
	causeIE.Value.Cause = &ngapType.Cause{
		Present: ngapType.CausePresentMisc,
		Misc:    &ngapType.CauseMisc{Value: ngapType.CauseMiscPresentOmIntervention},
	}
	ies.List = append(ies.List, causeIE)

	rtIE := ngapType.NGResetIEs{}
	rtIE.Id.Value = ngapType.ProtocolIEIDResetType
	rtIE.Criticality.Value = ngapType.CriticalityPresentReject
	rtIE.Value.Present = ngapType.NGResetIEsPresentResetType
	rtIE.Value.ResetType = new(ngapType.ResetType)

	if len(connections) == 0 {
		rtIE.Value.ResetType.Present = ngapType.ResetTypePresentNGInterface
		rtIE.Value.ResetType.NGInterface = &ngapType.ResetAll{Value: ngapType.ResetAllPresentResetAll}
	} else {
		rtIE.Value.ResetType.Present = ngapType.ResetTypePresentPartOfNGInterface
		list := new(ngapType.UEAssociatedLogicalNGConnectionList)

		for _, c := range connections {
			item := ngapType.UEAssociatedLogicalNGConnectionItem{}
			if c.AmfUeNgapID != nil {
				item.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: *c.AmfUeNgapID}
			}

			if c.RanUeNgapID != nil {
				item.RANUENGAPID = &ngapType.RANUENGAPID{Value: *c.RanUeNgapID}
			}

			list.List = append(list.List, item)
		}

		rtIE.Value.ResetType.PartOfNGInterface = list
	}

	ies.List = append(ies.List, rtIE)

	return ngap.Encoder(pdu)
}

// HandoverAdmittedSession is a PDU session admitted by the target gNB in a
// Handover Request Acknowledge, with its downlink GTP tunnel. RawTransfer, when
// set, replaces the built transfer verbatim — for crafting malformed transfers.
type HandoverAdmittedSession struct {
	PDUSessionID int64
	DLTeid       uint32
	DLIP         string
	RawTransfer  []byte
}

// BuildHandoverRequired builds a HANDOVER REQUIRED (TS 38.413 §8.4.1) sent by
// the source gNB. The source-to-target container and per-session transfer are
// opaque to the AMF, so placeholders suffice.
func BuildHandoverRequired(amfUeNgapID, ranUeNgapID int64, targetGnbID, mcc, mnc, tac string, pduSessionIDs []int64, causeRadioNetwork int64) ([]byte, error) {
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
		ngapType.HandoverRequiredIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}

	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.HandoverRequiredIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}

	add(ngapType.ProtocolIEIDHandoverType, ngapType.CriticalityPresentReject,
		ngapType.HandoverRequiredIEsPresentHandoverType).HandoverType = &ngapType.HandoverType{Value: ngapType.HandoverTypePresentIntra5gs}

	add(ngapType.ProtocolIEIDCause, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverRequiredIEsPresentCause).Cause = &ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: aper.Enumerated(causeRadioNetwork)},
	}

	plmnID, err := encodePLMN(mcc, mnc)
	if err != nil {
		return nil, fmt.Errorf("target PLMN: %w", err)
	}

	tacBytes, err := GetTacInBytes(tac)
	if err != nil {
		return nil, fmt.Errorf("target TAC: %w", err)
	}

	gnbIDBits := ngapConvert.HexToBitString(targetGnbID, 24)
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
	for _, id := range pduSessionIDs {
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

// BuildHandoverRequestAcknowledge builds a HANDOVER REQUEST ACKNOWLEDGE
// (TS 38.413 §8.4.2) sent by the target gNB.
func BuildHandoverRequestAcknowledge(amfUeNgapID, ranUeNgapID int64, sessions []HandoverAdmittedSession, failed []int64) ([]byte, error) {
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
		ngapType.HandoverRequestAcknowledgeIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}

	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentIgnore,
		ngapType.HandoverRequestAcknowledgeIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}

	admitted := &ngapType.PDUSessionResourceAdmittedList{}
	for _, s := range sessions {
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

	// Report the non-admitted PDU sessions in the failed-to-setup list
	// (TS 38.413 §8.4.2.2).
	if len(failed) > 0 {
		unsuccessful, err := buildHandoverResourceAllocationUnsuccessfulTransfer()
		if err != nil {
			return nil, err
		}

		failedList := &ngapType.PDUSessionResourceFailedToSetupListHOAck{}
		for _, id := range failed {
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

// buildHandoverResourceAllocationUnsuccessfulTransfer encodes the per-session
// failure transfer carried for each non-admitted PDU session (TS 38.413
// §9.3.4.16).
func buildHandoverResourceAllocationUnsuccessfulTransfer() ([]byte, error) {
	transfer := ngapType.HandoverResourceAllocationUnsuccessfulTransfer{
		Cause: ngapType.Cause{
			Present:      ngapType.CausePresentRadioNetwork,
			RadioNetwork: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable},
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

	tacBytes, err := GetTacInBytes(tac)
	if err != nil {
		return nil, fmt.Errorf("TAC: %w", err)
	}

	nrCellID, err := GetNRCellIdentity(gnbID)
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
			RadioNetwork: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable},
		},
	}

	buf, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil, fmt.Errorf("marshal PathSwitchRequestSetupFailedTransfer: %w", err)
	}

	return buf, nil
}

// CauseRadioNetworkHandoverDesirableForRadioReason is the radio-network Cause
// value "handover-desirable-for-radio-reason" (TS 38.413 §9.3.1.2), the usual
// trigger for a source NG-RAN node's Handover Required.
const CauseRadioNetworkHandoverDesirableForRadioReason int64 = 16

// CauseRadioNetworkHandoverCancelled is the radio-network Cause value
// "handover-cancelled" (TS 38.413 §9.3.1.2).
const CauseRadioNetworkHandoverCancelled int64 = 5

// CauseRadioNetworkHoFailureInTarget is the radio-network Cause value
// "ho-failure-in-target-5GC-ngran-node-or-target-system" (TS 38.413 §9.3.1.2).
const CauseRadioNetworkHoFailureInTarget int64 = 7

// BuildHandoverFailure builds a HANDOVER FAILURE (TS 38.413 §8.4.2.3) sent by
// the target gNB when it cannot admit a handover. It carries the AMF UE NGAP ID
// and a radio-network Cause (§9.2.3.6).
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

// BuildHandoverCancel builds a HANDOVER CANCEL (TS 38.413 §8.4.5) sent by the
// source gNB to abort an ongoing or already-prepared handover. The Cause is a
// radio-network value (TS 38.413 §9.3.1.2).
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

// DRBStatusTransferItem is one DRB's preserved PDCP state for an UPLINK RAN
// STATUS TRANSFER (TS 38.413 §8.4.6.2): the source NG-RAN node reports the DRB
// ID with its UL and DL COUNT for every DRB subject to status transfer.
type DRBStatusTransferItem struct {
	DRBID    int64
	ULPDCPSN int64
	ULHFN    int64
	DLPDCPSN int64
	DLHFN    int64
}

// BuildUplinkRANStatusTransfer builds an UPLINK RAN STATUS TRANSFER (TS 38.413
// §8.4.6) sent by the source NG-RAN node to hand the AMF the PDCP SN/HFN status
// the target needs for a lossless handover. The COUNT values use the 12-bit
// PDCP-SN alternative (TS 38.413 §9.3.1.108).
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

// BuildHandoverNotify builds a HANDOVER NOTIFY (TS 38.413 §8.4.3) sent by the
// target gNB once the UE has arrived.
func BuildHandoverNotify(amfUeNgapID, ranUeNgapID int64, mcc, mnc, tac, gnbID string) ([]byte, error) {
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
		ngapType.HandoverNotifyIEsPresentAMFUENGAPID).AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}

	add(ngapType.ProtocolIEIDRANUENGAPID, ngapType.CriticalityPresentReject,
		ngapType.HandoverNotifyIEsPresentRANUENGAPID).RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}

	plmnID, err := encodePLMN(mcc, mnc)
	if err != nil {
		return nil, fmt.Errorf("PLMN: %w", err)
	}

	tacBytes, err := GetTacInBytes(tac)
	if err != nil {
		return nil, fmt.Errorf("TAC: %w", err)
	}

	nrCellID, err := GetNRCellIdentity(gnbID)
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

	amfIE := ngapType.PDUSessionResourceReleaseResponseIEs{}
	amfIE.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amfIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	amfIE.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentAMFUENGAPID
	amfIE.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	amfIE.Value.AMFUENGAPID.Value = amfUeNgapID
	ies.List = append(ies.List, amfIE)

	ranIE := ngapType.PDUSessionResourceReleaseResponseIEs{}
	ranIE.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ranIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	ranIE.Value.Present = ngapType.PDUSessionResourceReleaseResponseIEsPresentRANUENGAPID
	ranIE.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ranIE.Value.RANUENGAPID.Value = ranUeNgapID
	ies.List = append(ies.List, ranIE)

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

	amfIE := ngapType.InitialContextSetupResponseIEs{}
	amfIE.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amfIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	amfIE.Value.Present = ngapType.InitialContextSetupResponseIEsPresentAMFUENGAPID
	amfIE.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	amfIE.Value.AMFUENGAPID.Value = amfUeNgapID
	ies.List = append(ies.List, amfIE)

	ranIE := ngapType.InitialContextSetupResponseIEs{}
	ranIE.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ranIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	ranIE.Value.Present = ngapType.InitialContextSetupResponseIEsPresentRANUENGAPID
	ranIE.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ranIE.Value.RANUENGAPID.Value = ranUeNgapID
	ies.List = append(ies.List, ranIE)

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

	amfIE := ngapType.UEContextReleaseCompleteIEs{}
	amfIE.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amfIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	amfIE.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentAMFUENGAPID
	amfIE.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	amfIE.Value.AMFUENGAPID.Value = amfUeNgapID
	ies.List = append(ies.List, amfIE)

	ranIE := ngapType.UEContextReleaseCompleteIEs{}
	ranIE.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ranIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	ranIE.Value.Present = ngapType.UEContextReleaseCompleteIEsPresentRANUENGAPID
	ranIE.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ranIE.Value.RANUENGAPID.Value = ranUeNgapID
	ies.List = append(ies.List, ranIE)

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

	amfIE := ngapType.UEContextReleaseRequestIEs{}
	amfIE.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amfIE.Criticality.Value = ngapType.CriticalityPresentReject
	amfIE.Value.Present = ngapType.UEContextReleaseRequestIEsPresentAMFUENGAPID
	amfIE.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	amfIE.Value.AMFUENGAPID.Value = amfUeNgapID
	ies.List = append(ies.List, amfIE)

	ranIE := ngapType.UEContextReleaseRequestIEs{}
	ranIE.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ranIE.Criticality.Value = ngapType.CriticalityPresentReject
	ranIE.Value.Present = ngapType.UEContextReleaseRequestIEsPresentRANUENGAPID
	ranIE.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	ranIE.Value.RANUENGAPID.Value = ranUeNgapID
	ies.List = append(ies.List, ranIE)

	causeIE := ngapType.UEContextReleaseRequestIEs{}
	causeIE.Id.Value = ngapType.ProtocolIEIDCause
	causeIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	causeIE.Value.Present = ngapType.UEContextReleaseRequestIEsPresentCause
	causeIE.Value.Cause = new(ngapType.Cause)
	causeIE.Value.Cause.Present = ngapType.CausePresentRadioNetwork
	causeIE.Value.Cause.RadioNetwork = new(ngapType.CauseRadioNetwork)
	causeIE.Value.Cause.RadioNetwork.Value = aper.Enumerated(causeRadioNetwork)
	ies.List = append(ies.List, causeIE)

	return ngap.Encoder(pdu)
}
