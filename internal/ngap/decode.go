package ngap

import (
	"encoding/hex"
	"fmt"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func Decode(data []byte) (*NGAPResponse, error) {
	pdu, err := ngap.Decoder(data)
	if err != nil {
		return nil, fmt.Errorf("ngap decode: %w", err)
	}

	resp := &NGAPResponse{
		RawHex: hex.EncodeToString(data),
	}

	switch pdu.Present {
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		resp.PDUType = "successful_outcome"
		resp.MessageType = getSuccessfulOutcomeName(pdu.SuccessfulOutcome.Value.Present)
		decodeSuccessfulOutcome(pdu.SuccessfulOutcome, resp)

	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		resp.PDUType = "unsuccessful_outcome"
		resp.MessageType = getUnsuccessfulOutcomeName(pdu.UnsuccessfulOutcome.Value.Present)
		decodeUnsuccessfulOutcome(pdu.UnsuccessfulOutcome, resp)

	case ngapType.NGAPPDUPresentInitiatingMessage:
		resp.PDUType = "initiating_message"
		resp.MessageType = getInitiatingMessageName(pdu.InitiatingMessage.Value.Present)
		decodeInitiatingMessage(pdu.InitiatingMessage, resp)

	default:
		return nil, fmt.Errorf("unknown NGAP PDU present: %d", pdu.Present)
	}

	return resp, nil
}

func decodeSuccessfulOutcome(so *ngapType.SuccessfulOutcome, resp *NGAPResponse) {
	switch so.Value.Present {
	case ngapType.SuccessfulOutcomePresentNGSetupResponse:
		decodeNGSetupResponse(so.Value.NGSetupResponse, resp)
	}
}

func decodeUnsuccessfulOutcome(uo *ngapType.UnsuccessfulOutcome, resp *NGAPResponse) {
	switch uo.Value.Present {
	case ngapType.UnsuccessfulOutcomePresentNGSetupFailure:
		decodeNGSetupFailure(uo.Value.NGSetupFailure, resp)
	}
}

func decodeInitiatingMessage(im *ngapType.InitiatingMessage, resp *NGAPResponse) {
	switch im.Value.Present {
	case ngapType.InitiatingMessagePresentDownlinkNASTransport:
		decodeDownlinkNASTransport(im.Value.DownlinkNASTransport, resp)
	case ngapType.InitiatingMessagePresentInitialContextSetupRequest:
		decodeInitialContextSetupRequest(im.Value.InitialContextSetupRequest, resp)
	case ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest:
		decodePDUSessionResourceSetupRequest(im.Value.PDUSessionResourceSetupRequest, resp)
	}
}

func decodeInitialContextSetupRequest(msg *ngapType.InitialContextSetupRequest, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityToString(ie.Criticality.Value),
		}

		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				decoded.AmfUeNgapID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				decoded.RanUeNgapID = &v
			}
		case ngapType.ProtocolIEIDNASPDU:
			if ie.Value.NASPDU != nil {
				s := hex.EncodeToString(ie.Value.NASPDU.Value)
				decoded.NasPDU = &s
			}
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			if ie.Value.UEAggregateMaximumBitRate != nil {
				decoded.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
					DL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value,
					UL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value,
				}
			}
		case ngapType.ProtocolIEIDAllowedNSSAI:
			if ie.Value.AllowedNSSAI != nil {
				for _, item := range ie.Value.AllowedNSSAI.List {
					nssai := AllowedNSSAIItemJSON{
						SST: hex.EncodeToString(item.SNSSAI.SST.Value),
					}
					if item.SNSSAI.SD != nil {
						nssai.SD = hex.EncodeToString(item.SNSSAI.SD.Value)
					}
					decoded.AllowedNSSAI = append(decoded.AllowedNSSAI, nssai)
				}
			}
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodeDownlinkNASTransport(msg *ngapType.DownlinkNASTransport, resp *NGAPResponse) {
	if msg == nil {
		return
	}
	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityToString(ie.Criticality.Value),
		}

		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				decoded.AmfUeNgapID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				decoded.RanUeNgapID = &v
			}
		case ngapType.ProtocolIEIDNASPDU:
			if ie.Value.NASPDU != nil {
				s := hex.EncodeToString(ie.Value.NASPDU.Value)
				decoded.NasPDU = &s
			}
		case ngapType.ProtocolIEIDOldAMF:
			if ie.Value.OldAMF != nil {
				s := ie.Value.OldAMF.Value
				decoded.OldAMF = &s
			}
		case ngapType.ProtocolIEIDRANPagingPriority:
			if ie.Value.RANPagingPriority != nil {
				v := int64(ie.Value.RANPagingPriority.Value)
				decoded.RANPagingPriority = &v
			}
		case ngapType.ProtocolIEIDMobilityRestrictionList:
			if ie.Value.MobilityRestrictionList != nil {
				mrl := &MobilityRestrictionListJSON{
					ServingPLMN: hex.EncodeToString(ie.Value.MobilityRestrictionList.ServingPLMN.Value),
				}
				if ie.Value.MobilityRestrictionList.EquivalentPLMNs != nil {
					for _, p := range ie.Value.MobilityRestrictionList.EquivalentPLMNs.List {
						mrl.EquivalentPLMNs = append(mrl.EquivalentPLMNs, hex.EncodeToString(p.Value))
					}
				}
				decoded.MobilityRestrictionList = mrl
			}
		case ngapType.ProtocolIEIDIndexToRFSP:
			if ie.Value.IndexToRFSP != nil {
				v := ie.Value.IndexToRFSP.Value
				decoded.IndexToRFSP = &v
			}
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			if ie.Value.UEAggregateMaximumBitRate != nil {
				decoded.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
					DL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value,
					UL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value,
				}
			}
		case ngapType.ProtocolIEIDAllowedNSSAI:
			if ie.Value.AllowedNSSAI != nil {
				for _, item := range ie.Value.AllowedNSSAI.List {
					nssai := AllowedNSSAIItemJSON{
						SST: hex.EncodeToString(item.SNSSAI.SST.Value),
					}
					if item.SNSSAI.SD != nil {
						nssai.SD = hex.EncodeToString(item.SNSSAI.SD.Value)
					}
					decoded.AllowedNSSAI = append(decoded.AllowedNSSAI, nssai)
				}
			}
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodePDUSessionResourceSetupRequest(msg *ngapType.PDUSessionResourceSetupRequest, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityToString(ie.Criticality.Value),
		}

		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				decoded.AmfUeNgapID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				decoded.RanUeNgapID = &v
			}
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			if ie.Value.UEAggregateMaximumBitRate != nil {
				decoded.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
					DL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value,
					UL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value,
				}
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq:
			if ie.Value.PDUSessionResourceSetupListSUReq != nil {
				for _, item := range ie.Value.PDUSessionResourceSetupListSUReq.List {
					if item.PDUSessionNASPDU != nil {
						s := hex.EncodeToString(item.PDUSessionNASPDU.Value)
						decoded.NasPDU = &s
					}
				}
			}
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodeNGSetupResponse(msg *ngapType.NGSetupResponse, resp *NGAPResponse) {
	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityToString(ie.Criticality.Value),
		}

		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFName:
			if ie.Value.AMFName != nil {
				name := ie.Value.AMFName.Value
				decoded.AMFName = &name
			}

		case ngapType.ProtocolIEIDServedGUAMIList:
			if ie.Value.ServedGUAMIList != nil {
				for _, item := range ie.Value.ServedGUAMIList.List {
					guami := ServedGUAMIJSON{
						PLMNIdentity: hex.EncodeToString(item.GUAMI.PLMNIdentity.Value),
						AMFRegionID:  hex.EncodeToString(item.GUAMI.AMFRegionID.Value.Bytes),
						AMFSetID:     hex.EncodeToString(item.GUAMI.AMFSetID.Value.Bytes),
						AMFPointer:   hex.EncodeToString(item.GUAMI.AMFPointer.Value.Bytes),
					}
					decoded.ServedGUAMIList = append(decoded.ServedGUAMIList, guami)
				}
			}

		case ngapType.ProtocolIEIDRelativeAMFCapacity:
			if ie.Value.RelativeAMFCapacity != nil {
				v := ie.Value.RelativeAMFCapacity.Value
				decoded.RelativeAMFCapacity = &v
			}

		case ngapType.ProtocolIEIDPLMNSupportList:
			if ie.Value.PLMNSupportList != nil {
				for _, item := range ie.Value.PLMNSupportList.List {
					plmn := PLMNSupportJSON{
						PLMNIdentity: hex.EncodeToString(item.PLMNIdentity.Value),
					}
					for _, sliceItem := range item.SliceSupportList.List {
						ss := SliceSupportJSON{
							SST: hex.EncodeToString(sliceItem.SNSSAI.SST.Value),
						}
						if sliceItem.SNSSAI.SD != nil {
							ss.SD = hex.EncodeToString(sliceItem.SNSSAI.SD.Value)
						}
						plmn.SliceSupport = append(plmn.SliceSupport, ss)
					}
					decoded.PLMNSupportList = append(decoded.PLMNSupportList, plmn)
				}
			}

		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			if ie.Value.CriticalityDiagnostics != nil {
				decoded.CriticalityDiagnostics = decodeCriticalityDiagnostics(ie.Value.CriticalityDiagnostics)
			}

		case ngapType.ProtocolIEIDUERetentionInformation:
			if ie.Value.UERetentionInformation != nil {
				v := int64(ie.Value.UERetentionInformation.Value)
				decoded.UERetentionInformation = &v
			}
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodeNGSetupFailure(msg *ngapType.NGSetupFailure, resp *NGAPResponse) {
	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityToString(ie.Criticality.Value),
		}

		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				decoded.Cause = decodeCause(ie.Value.Cause)
			}

		case ngapType.ProtocolIEIDTimeToWait:
			if ie.Value.TimeToWait != nil {
				v := int64(ie.Value.TimeToWait.Value)
				decoded.TimeToWait = &v
			}

		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			if ie.Value.CriticalityDiagnostics != nil {
				decoded.CriticalityDiagnostics = decodeCriticalityDiagnostics(ie.Value.CriticalityDiagnostics)
			}
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodeCause(cause *ngapType.Cause) *CauseJSON {
	c := &CauseJSON{}
	switch cause.Present {
	case ngapType.CausePresentRadioNetwork:
		c.Present = "radio_network"
		v := int64(cause.RadioNetwork.Value)
		c.RadioNetwork = &v
	case ngapType.CausePresentTransport:
		c.Present = "transport"
		v := int64(cause.Transport.Value)
		c.Transport = &v
	case ngapType.CausePresentNas:
		c.Present = "nas"
		v := int64(cause.Nas.Value)
		c.NAS = &v
	case ngapType.CausePresentProtocol:
		c.Present = "protocol"
		v := int64(cause.Protocol.Value)
		c.Protocol = &v
	case ngapType.CausePresentMisc:
		c.Present = "misc"
		v := int64(cause.Misc.Value)
		c.Misc = &v
	}
	return c
}

func decodeCriticalityDiagnostics(cd *ngapType.CriticalityDiagnostics) *CriticalityDiagnosticsJSON {
	out := &CriticalityDiagnosticsJSON{}
	if cd.ProcedureCode != nil {
		v := cd.ProcedureCode.Value
		out.ProcedureCode = &v
	}
	if cd.TriggeringMessage != nil {
		s := triggeringMessageToString(cd.TriggeringMessage.Value)
		out.TriggeringMessage = &s
	}
	if cd.ProcedureCriticality != nil {
		s := criticalityToString(cd.ProcedureCriticality.Value)
		out.ProcedureCriticality = &s
	}
	if cd.IEsCriticalityDiagnostics != nil {
		for _, item := range cd.IEsCriticalityDiagnostics.List {
			out.IEsCriticalityDiagnostics = append(out.IEsCriticalityDiagnostics, IECriticalityDiagnosticJSON{
				IECriticality: criticalityToString(item.IECriticality.Value),
				IEID:          item.IEID.Value,
				TypeOfError:   typeOfErrorToString(item.TypeOfError.Value),
			})
		}
	}
	return out
}

func triggeringMessageToString(v aper.Enumerated) string {
	switch v {
	case ngapType.TriggeringMessagePresentInitiatingMessage:
		return "initiating_message"
	case ngapType.TriggeringMessagePresentSuccessfulOutcome:
		return "successful_outcome"
	case ngapType.TriggeringMessagePresentUnsuccessfullOutcome:
		return "unsuccessful_outcome"
	default:
		return "unknown"
	}
}

func typeOfErrorToString(v aper.Enumerated) string {
	switch v {
	case ngapType.TypeOfErrorPresentNotUnderstood:
		return "not_understood"
	case ngapType.TypeOfErrorPresentMissing:
		return "missing"
	default:
		return "unknown"
	}
}

func criticalityToString(c aper.Enumerated) string {
	switch c {
	case ngapType.CriticalityPresentReject:
		return "reject"
	case ngapType.CriticalityPresentIgnore:
		return "ignore"
	case ngapType.CriticalityPresentNotify:
		return "notify"
	default:
		return "ignore"
	}
}

func getInitiatingMessageName(msgType int) string {
	switch msgType {
	case ngapType.InitiatingMessagePresentDownlinkNASTransport:
		return "DownlinkNASTransport"
	case ngapType.InitiatingMessagePresentInitialContextSetupRequest:
		return "InitialContextSetupRequest"
	case ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest:
		return "PDUSessionResourceSetupRequest"
	case ngapType.InitiatingMessagePresentUEContextReleaseCommand:
		return "UEContextReleaseCommand"
	case ngapType.InitiatingMessagePresentPaging:
		return "Paging"
	case ngapType.InitiatingMessagePresentErrorIndication:
		return "ErrorIndication"
	case ngapType.InitiatingMessagePresentNGSetupRequest:
		return "NGSetupRequest"
	case ngapType.InitiatingMessagePresentNGReset:
		return "NGReset"
	case ngapType.InitiatingMessagePresentInitialUEMessage:
		return "InitialUEMessage"
	case ngapType.InitiatingMessagePresentUplinkNASTransport:
		return "UplinkNASTransport"
	default:
		return fmt.Sprintf("Unknown(%d)", msgType)
	}
}

func getSuccessfulOutcomeName(msgType int) string {
	switch msgType {
	case ngapType.SuccessfulOutcomePresentNGSetupResponse:
		return "NGSetupResponse"
	case ngapType.SuccessfulOutcomePresentNGResetAcknowledge:
		return "NGResetAcknowledge"
	case ngapType.SuccessfulOutcomePresentInitialContextSetupResponse:
		return "InitialContextSetupResponse"
	case ngapType.SuccessfulOutcomePresentPDUSessionResourceSetupResponse:
		return "PDUSessionResourceSetupResponse"
	case ngapType.SuccessfulOutcomePresentUEContextReleaseComplete:
		return "UEContextReleaseComplete"
	case ngapType.SuccessfulOutcomePresentPathSwitchRequestAcknowledge:
		return "PathSwitchRequestAcknowledge"
	default:
		return fmt.Sprintf("Unknown(%d)", msgType)
	}
}

func getUnsuccessfulOutcomeName(msgType int) string {
	switch msgType {
	case ngapType.UnsuccessfulOutcomePresentNGSetupFailure:
		return "NGSetupFailure"
	case ngapType.UnsuccessfulOutcomePresentPathSwitchRequestFailure:
		return "PathSwitchRequestFailure"
	case ngapType.UnsuccessfulOutcomePresentInitialContextSetupFailure:
		return "InitialContextSetupFailure"
	default:
		return fmt.Sprintf("Unknown(%d)", msgType)
	}
}
