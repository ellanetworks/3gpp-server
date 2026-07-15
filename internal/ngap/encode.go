// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

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
