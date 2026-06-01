package ngap

import (
	"encoding/hex"
	"fmt"

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

func BuildInitialUEMessageFromState(ranUeNgapID int64, nasPDU []byte, mcc, mnc, tac, gnbID string, guti *FiveGSTMSIFromGUTI, overrides *InitialUEMessageOverrides) *NGAPMessage {
	plmnID, _ := GetMccAndMncInOctets(mcc, mnc)
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
	}
}

type FiveGSTMSIFromGUTI struct {
	AMFSetID   string
	AMFPointer string
	FiveGTMSI  string
}

// BuildNGSetupRequestFromStore builds the IE-level NGAPMessage for an
// NGSetupRequest using stored gNB context values. This is the convenience
// path — the caller can override any IE afterward.
func BuildNGSetupRequestFromStore(mcc, mnc, tac, gnbID, name string, sst int32, sd string, slices []struct{ SST int32; SD string }) *NGAPMessage {
	plmnID, _ := GetMccAndMncInOctets(mcc, mnc)
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
				ID:              ngapType.ProtocolIEIDDefaultPagingDRX,
				Criticality:     "ignore",
				DefaultPagingDRX: &pagingDRX,
			},
		},
	}
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
	plmnID := GetPLMNIdentity(mcc, mnc)
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

func BuildPDUSessionResourceSetupResponse(amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
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
