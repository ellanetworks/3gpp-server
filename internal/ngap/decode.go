// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func decodeULTunnel(transfer []byte) (teid uint32, ipv4, ipv6 string, ok bool) {
	var t ngapType.PDUSessionResourceSetupRequestTransfer
	if err := aper.UnmarshalWithParams(transfer, &t, "valueExt"); err != nil {
		return 0, "", "", false
	}

	for _, ie := range t.ProtocolIEs.List {
		if ie.Id.Value != ngapType.ProtocolIEIDULNGUUPTNLInformation || ie.Value.ULNGUUPTNLInformation == nil {
			continue
		}

		gt := ie.Value.ULNGUUPTNLInformation.GTPTunnel
		if gt == nil || len(gt.GTPTEID.Value) < 4 {
			continue
		}

		teid = binary.BigEndian.Uint32(gt.GTPTEID.Value)

		// TransportLayerAddress: 32-bit IPv4, 128-bit IPv6, or 160-bit carrying the IPv4 in the first 32 bits (TS 38.413).
		b := gt.TransportLayerAddress.Value.Bytes
		switch len(b) {
		case 4:
			if a, aok := netip.AddrFromSlice(b); aok {
				ipv4 = a.String()
			}
		case 16:
			if a, aok := netip.AddrFromSlice(b); aok {
				ipv6 = a.Unmap().String()
			}
		case 20:
			if a, aok := netip.AddrFromSlice(b[0:4]); aok {
				ipv4 = a.String()
			}
			if a, aok := netip.AddrFromSlice(b[4:20]); aok {
				ipv6 = a.Unmap().String()
			}
		}

		return teid, ipv4, ipv6, true
	}

	return 0, "", "", false
}

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
		resp.MessageType = successfulOutcomeName(pdu.SuccessfulOutcome.Value.Present, pdu.SuccessfulOutcome.ProcedureCode.Value)
		decodeSuccessfulOutcome(pdu.SuccessfulOutcome, resp)

	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		resp.PDUType = "unsuccessful_outcome"
		resp.MessageType = unsuccessfulOutcomeName(pdu.UnsuccessfulOutcome.Value.Present, pdu.UnsuccessfulOutcome.ProcedureCode.Value)
		decodeUnsuccessfulOutcome(pdu.UnsuccessfulOutcome, resp)

	case ngapType.NGAPPDUPresentInitiatingMessage:
		resp.PDUType = "initiating_message"
		resp.MessageType = initiatingMessageName(pdu.InitiatingMessage.Value.Present, pdu.InitiatingMessage.ProcedureCode.Value)
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
	case ngapType.SuccessfulOutcomePresentNGResetAcknowledge:
		decodeNGResetAcknowledge(so.Value.NGResetAcknowledge, resp)
	case ngapType.SuccessfulOutcomePresentHandoverCommand:
		decodeHandoverCommand(so.Value.HandoverCommand, resp)
	case ngapType.SuccessfulOutcomePresentHandoverCancelAcknowledge:
		decodeHandoverCancelAcknowledge(so.Value.HandoverCancelAcknowledge, resp)
	case ngapType.SuccessfulOutcomePresentPathSwitchRequestAcknowledge:
		decodePathSwitchRequestAcknowledge(so.Value.PathSwitchRequestAcknowledge, resp)
	}
}

func decodePathSwitchRequestAcknowledge(msg *ngapType.PathSwitchRequestAcknowledge, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDUESecurityCapabilities:
			if ie.Value.UESecurityCapabilities != nil {
				resp.UESecurityCapabilities = decodeUESecurityCapabilities(ie.Value.UESecurityCapabilities)
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSwitchedList:
			if ie.Value.PDUSessionResourceSwitchedList != nil {
				for _, item := range ie.Value.PDUSessionResourceSwitchedList.List {
					resp.PDUSessionIDs = append(resp.PDUSessionIDs, item.PDUSessionID.Value)
				}
			}
		case ngapType.ProtocolIEIDPDUSessionResourceReleasedListPSAck:
			if ie.Value.PDUSessionResourceReleasedListPSAck != nil {
				for _, item := range ie.Value.PDUSessionResourceReleasedListPSAck.List {
					resp.ReleasePDUSessionIDs = append(resp.ReleasePDUSessionIDs, item.PDUSessionID.Value)
				}
			}
		case ngapType.ProtocolIEIDSecurityContext:
			if sc := ie.Value.SecurityContext; sc != nil {
				nh := hex.EncodeToString(sc.NextHopNH.Value.Bytes)
				resp.SecurityContext = &SecurityContextJSON{NextHopChainingCount: int(sc.NextHopChainingCount.Value), NextHop: nh}
			}
		case ngapType.ProtocolIEIDAllowedNSSAI:
			if ie.Value.AllowedNSSAI != nil {
				resp.AllowedNSSAI = decodeAllowedNSSAI(ie.Value.AllowedNSSAI)
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeAllowedNSSAI(list *ngapType.AllowedNSSAI) []AllowedNSSAIItemJSON {
	items := make([]AllowedNSSAIItemJSON, 0, len(list.List))

	for _, item := range list.List {
		nssai := AllowedNSSAIItemJSON{SST: hex.EncodeToString(item.SNSSAI.SST.Value)}
		if item.SNSSAI.SD != nil {
			nssai.SD = hex.EncodeToString(item.SNSSAI.SD.Value)
		}

		items = append(items, nssai)
	}

	return items
}

func decodeUESecurityCapabilities(caps *ngapType.UESecurityCapabilities) *UESecurityCapabilitiesJSON {
	return &UESecurityCapabilitiesJSON{
		NREncryption:    hex.EncodeToString(caps.NRencryptionAlgorithms.Value.Bytes),
		NRIntegrity:     hex.EncodeToString(caps.NRintegrityProtectionAlgorithms.Value.Bytes),
		EUTRAEncryption: hex.EncodeToString(caps.EUTRAencryptionAlgorithms.Value.Bytes),
		EUTRAIntegrity:  hex.EncodeToString(caps.EUTRAintegrityProtectionAlgorithms.Value.Bytes),
	}
}

func decodeHandoverCancelAcknowledge(msg *ngapType.HandoverCancelAcknowledge, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeHandoverCommand(msg *ngapType.HandoverCommand, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDPDUSessionResourceHandoverList:
			if list := ie.Value.PDUSessionResourceHandoverList; list != nil {
				ids := make([]int64, 0, len(list.List))
				for _, item := range list.List {
					ids = append(ids, item.PDUSessionID.Value)
				}
				resp.PDUSessionIDs = ids
			}
		case ngapType.ProtocolIEIDPDUSessionResourceToReleaseListHOCmd:
			if list := ie.Value.PDUSessionResourceToReleaseListHOCmd; list != nil {
				ids := make([]int64, 0, len(list.List))
				for _, item := range list.List {
					ids = append(ids, item.PDUSessionID.Value)
				}
				resp.ReleasePDUSessionIDs = ids
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeNGResetAcknowledge(msg *ngapType.NGResetAcknowledge, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		if ie.Id.Value != ngapType.ProtocolIEIDUEAssociatedLogicalNGConnectionList ||
			ie.Value.UEAssociatedLogicalNGConnectionList == nil {
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
			continue
		}

		for _, item := range ie.Value.UEAssociatedLogicalNGConnectionList.List {
			conn := ResetConnectionJSON{}

			if item.AMFUENGAPID != nil {
				v := item.AMFUENGAPID.Value
				conn.AMFUENGAPID = &v
			}

			if item.RANUENGAPID != nil {
				v := item.RANUENGAPID.Value
				conn.RANUENGAPID = &v
			}

			resp.ResetConnections = append(resp.ResetConnections, conn)
		}
	}
}

func decodeUnsuccessfulOutcome(uo *ngapType.UnsuccessfulOutcome, resp *NGAPResponse) {
	switch uo.Value.Present {
	case ngapType.UnsuccessfulOutcomePresentNGSetupFailure:
		decodeNGSetupFailure(uo.Value.NGSetupFailure, resp)
	case ngapType.UnsuccessfulOutcomePresentHandoverPreparationFailure:
		decodeHandoverPreparationFailure(uo.Value.HandoverPreparationFailure, resp)
	case ngapType.UnsuccessfulOutcomePresentPathSwitchRequestFailure:
		decodePathSwitchRequestFailure(uo.Value.PathSwitchRequestFailure, resp)
	}
}

func decodePathSwitchRequestFailure(msg *ngapType.PathSwitchRequestFailure, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDPDUSessionResourceReleasedListPSFail:
			if ie.Value.PDUSessionResourceReleasedListPSFail != nil {
				for _, item := range ie.Value.PDUSessionResourceReleasedListPSFail.List {
					resp.ReleasePDUSessionIDs = append(resp.ReleasePDUSessionIDs, item.PDUSessionID.Value)
				}
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeHandoverPreparationFailure(msg *ngapType.HandoverPreparationFailure, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				resp.Cause = decodeCause(ie.Value.Cause)
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodePDUSessionResourceModifyRequest(msg *ngapType.PDUSessionResourceModifyRequest, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDPDUSessionResourceModifyListModReq:
			if ie.Value.PDUSessionResourceModifyListModReq != nil {
				for i := range ie.Value.PDUSessionResourceModifyListModReq.List {
					if nasPDU := ie.Value.PDUSessionResourceModifyListModReq.List[i].NASPDU; nasPDU != nil && resp.NasPDU == nil {
						s := hex.EncodeToString(nasPDU.Value)
						resp.NasPDU = &s
					}
				}
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func unknownIE(id int64, crit aper.Enumerated, value any) UnknownIEJSON {
	return UnknownIEJSON{
		ID:          id,
		Criticality: criticalityName(crit),
		ValueHex:    unmodeledIEHex(value),
	}
}

// Re-encodes an unmodeled IE's CHOICE value so its octets survive; empty when aper discarded them (id absent from the message CHOICE).
func unmodeledIEHex(v any) string {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Struct || rv.NumField() == 0 {
		return ""
	}

	present := int(rv.Field(0).Int())
	if present <= 0 || present >= rv.NumField() {
		return ""
	}

	alt := rv.Field(present)
	if alt.Kind() == reflect.Pointer && alt.IsNil() {
		return ""
	}

	octets, err := aper.MarshalWithParams(alt.Interface(), rv.Type().Field(present).Tag.Get("aper"))
	if err != nil {
		return ""
	}

	return hex.EncodeToString(octets)
}

func decodeInitiatingMessage(im *ngapType.InitiatingMessage, resp *NGAPResponse) {
	switch im.Value.Present {
	case ngapType.InitiatingMessagePresentDownlinkNASTransport:
		decodeDownlinkNASTransport(im.Value.DownlinkNASTransport, resp)
	case ngapType.InitiatingMessagePresentInitialContextSetupRequest:
		decodeInitialContextSetupRequest(im.Value.InitialContextSetupRequest, resp)
	case ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest:
		decodePDUSessionResourceSetupRequest(im.Value.PDUSessionResourceSetupRequest, resp)
	case ngapType.InitiatingMessagePresentUEContextReleaseCommand:
		decodeUEContextReleaseCommand(im.Value.UEContextReleaseCommand, resp)
	case ngapType.InitiatingMessagePresentPDUSessionResourceReleaseCommand:
		decodePDUSessionResourceReleaseCommand(im.Value.PDUSessionResourceReleaseCommand, resp)
	case ngapType.InitiatingMessagePresentPDUSessionResourceModifyRequest:
		decodePDUSessionResourceModifyRequest(im.Value.PDUSessionResourceModifyRequest, resp)
	case ngapType.InitiatingMessagePresentHandoverRequest:
		decodeHandoverRequest(im.Value.HandoverRequest, resp)
	case ngapType.InitiatingMessagePresentErrorIndication:
		decodeErrorIndication(im.Value.ErrorIndication, resp)
	case ngapType.InitiatingMessagePresentPaging:
		decodePaging(im.Value.Paging, resp)
	case ngapType.InitiatingMessagePresentDownlinkRANStatusTransfer:
		decodeDownlinkRANStatusTransfer(im.Value.DownlinkRANStatusTransfer, resp)
	}
}

func decodeDownlinkRANStatusTransfer(msg *ngapType.DownlinkRANStatusTransfer, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANStatusTransferTransparentContainer:
			if ie.Value.RANStatusTransferTransparentContainer != nil {
				resp.RANStatusTransfer = decodeRANStatusTransferContainer(ie.Value.RANStatusTransferTransparentContainer)
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeRANStatusTransferContainer(c *ngapType.RANStatusTransferTransparentContainer) *RANStatusTransferJSON {
	out := &RANStatusTransferJSON{DRBs: make([]DRBStatusTransferItemJSON, 0, len(c.DRBsSubjectToStatusTransferList.List))}

	for i := range c.DRBsSubjectToStatusTransferList.List {
		item := &c.DRBsSubjectToStatusTransferList.List[i]
		d := DRBStatusTransferItemJSON{DRBID: item.DRBID.Value}

		if ul := item.DRBStatusUL.DRBStatusUL12; ul != nil {
			d.ULCount = &COUNTValueJSON{PDCPSN: ul.ULCOUNTValue.PDCPSN12, HFN: ul.ULCOUNTValue.HFNPDCPSN12}
		}

		if dl := item.DRBStatusDL.DRBStatusDL12; dl != nil {
			d.DLCount = &COUNTValueJSON{PDCPSN: dl.DLCOUNTValue.PDCPSN12, HFN: dl.DLCOUNTValue.HFNPDCPSN12}
		}

		out.DRBs = append(out.DRBs, d)
	}

	return out
}

func decodePaging(msg *ngapType.Paging, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDUEPagingIdentity &&
			ie.Value.UEPagingIdentity != nil && ie.Value.UEPagingIdentity.FiveGSTMSI != nil {
			resp.Paging = &PagingJSON{FiveGSTMSI: decodeFiveGSTMSI(ie.Value.UEPagingIdentity.FiveGSTMSI)}
		} else {
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeFiveGSTMSI(t *ngapType.FiveGSTMSI) *FiveGSTMSIJSON {
	return &FiveGSTMSIJSON{
		AMFSetID:   hex.EncodeToString(t.AMFSetID.Value.Bytes),
		AMFPointer: hex.EncodeToString(t.AMFPointer.Value.Bytes),
		FiveGTMSI:  hex.EncodeToString(t.FiveGTMSI.Value),
	}
}

func decodeErrorIndication(msg *ngapType.ErrorIndication, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				resp.Cause = decodeCause(ie.Value.Cause)
			}
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			if ie.Value.CriticalityDiagnostics != nil {
				resp.CriticalityDiagnostics = decodeCriticalityDiagnostics(ie.Value.CriticalityDiagnostics)
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeHandoverRequest(msg *ngapType.HandoverRequest, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListHOReq:
			if list := ie.Value.PDUSessionResourceSetupListHOReq; list != nil {
				ids := make([]int64, 0, len(list.List))
				for _, item := range list.List {
					ids = append(ids, item.PDUSessionID.Value)
				}
				resp.PDUSessionIDs = ids
			}
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			if ambr := ie.Value.UEAggregateMaximumBitRate; ambr != nil {
				resp.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
					DL: ambr.UEAggregateMaximumBitRateDL.Value,
					UL: ambr.UEAggregateMaximumBitRateUL.Value,
				}
			}
		case ngapType.ProtocolIEIDSecurityContext:
			if sc := ie.Value.SecurityContext; sc != nil {
				nh := hex.EncodeToString(sc.NextHopNH.Value.Bytes)
				resp.SecurityContext = &SecurityContextJSON{NextHopChainingCount: int(sc.NextHopChainingCount.Value), NextHop: nh}
			}
		case ngapType.ProtocolIEIDUESecurityCapabilities:
			if caps := ie.Value.UESecurityCapabilities; caps != nil {
				resp.UESecurityCapabilities = decodeUESecurityCapabilities(caps)
			}
		case ngapType.ProtocolIEIDSourceToTargetTransparentContainer:
			if c := ie.Value.SourceToTargetTransparentContainer; c != nil {
				s := hex.EncodeToString(c.Value)
				resp.SourceToTargetContainer = &s
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodePDUSessionResourceReleaseCommand(msg *ngapType.PDUSessionResourceReleaseCommand, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDNASPDU:
			if ie.Value.NASPDU != nil {
				s := hex.EncodeToString(ie.Value.NASPDU.Value)
				resp.NasPDU = &s
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeInitialContextSetupRequest(msg *ngapType.InitialContextSetupRequest, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDNASPDU:
			if ie.Value.NASPDU != nil {
				s := hex.EncodeToString(ie.Value.NASPDU.Value)
				resp.NasPDU = &s
			}
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			if ie.Value.UEAggregateMaximumBitRate != nil {
				resp.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
					DL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value,
					UL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value,
				}
			}
		case ngapType.ProtocolIEIDAllowedNSSAI:
			if ie.Value.AllowedNSSAI != nil {
				resp.AllowedNSSAI = decodeAllowedNSSAI(ie.Value.AllowedNSSAI)
			}
		case ngapType.ProtocolIEIDUERadioCapability:
			if ie.Value.UERadioCapability != nil {
				s := hex.EncodeToString(ie.Value.UERadioCapability.Value)
				resp.UERadioCapability = &s
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq:
			if ie.Value.PDUSessionResourceSetupListCxtReq != nil {
				for _, item := range ie.Value.PDUSessionResourceSetupListCxtReq.List {
					setupItem := PDUSessionSetupItemJSON{PDUSessionID: item.PDUSessionID.Value}
					if teid, ipv4, ipv6, ok := decodeULTunnel(item.PDUSessionResourceSetupRequestTransfer); ok {
						setupItem.ULTeid = teid
						setupItem.TransportLayerAddress = ipv4
						setupItem.TransportLayerAddressIPv6 = ipv6
					}

					resp.PDUSessionSetupItems = append(resp.PDUSessionSetupItems, setupItem)
				}
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeDownlinkNASTransport(msg *ngapType.DownlinkNASTransport, resp *NGAPResponse) {
	if msg == nil {
		return
	}
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDNASPDU:
			if ie.Value.NASPDU != nil {
				s := hex.EncodeToString(ie.Value.NASPDU.Value)
				resp.NasPDU = &s
			}
		case ngapType.ProtocolIEIDOldAMF:
			if ie.Value.OldAMF != nil {
				s := ie.Value.OldAMF.Value
				resp.OldAMF = &s
			}
		case ngapType.ProtocolIEIDRANPagingPriority:
			if ie.Value.RANPagingPriority != nil {
				v := int64(ie.Value.RANPagingPriority.Value)
				resp.RANPagingPriority = &v
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
				resp.MobilityRestrictionList = mrl
			}
		case ngapType.ProtocolIEIDIndexToRFSP:
			if ie.Value.IndexToRFSP != nil {
				v := ie.Value.IndexToRFSP.Value
				resp.IndexToRFSP = &v
			}
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			if ie.Value.UEAggregateMaximumBitRate != nil {
				resp.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
					DL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value,
					UL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value,
				}
			}
		case ngapType.ProtocolIEIDAllowedNSSAI:
			if ie.Value.AllowedNSSAI != nil {
				resp.AllowedNSSAI = decodeAllowedNSSAI(ie.Value.AllowedNSSAI)
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodePDUSessionResourceSetupRequest(msg *ngapType.PDUSessionResourceSetupRequest, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				v := ie.Value.AMFUENGAPID.Value
				resp.AMFUENGAPID = &v
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.RANUENGAPID = &v
			}
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			if ie.Value.UEAggregateMaximumBitRate != nil {
				resp.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
					DL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value,
					UL: ie.Value.UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value,
				}
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq:
			if ie.Value.PDUSessionResourceSetupListSUReq != nil {
				for _, item := range ie.Value.PDUSessionResourceSetupListSUReq.List {
					if item.PDUSessionNASPDU != nil && resp.NasPDU == nil {
						s := hex.EncodeToString(item.PDUSessionNASPDU.Value)
						resp.NasPDU = &s
					}

					setupItem := PDUSessionSetupItemJSON{PDUSessionID: item.PDUSessionID.Value}
					if teid, ipv4, ipv6, ok := decodeULTunnel(item.PDUSessionResourceSetupRequestTransfer); ok {
						setupItem.ULTeid = teid
						setupItem.TransportLayerAddress = ipv4
						setupItem.TransportLayerAddressIPv6 = ipv6
					}

					resp.PDUSessionSetupItems = append(resp.PDUSessionSetupItems, setupItem)
				}
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeNGSetupResponse(msg *ngapType.NGSetupResponse, resp *NGAPResponse) {
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFName:
			if ie.Value.AMFName != nil {
				name := ie.Value.AMFName.Value
				resp.AMFName = &name
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
					resp.ServedGUAMIList = append(resp.ServedGUAMIList, guami)
				}
			}

		case ngapType.ProtocolIEIDRelativeAMFCapacity:
			if ie.Value.RelativeAMFCapacity != nil {
				v := ie.Value.RelativeAMFCapacity.Value
				resp.RelativeAMFCapacity = &v
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
					resp.PLMNSupportList = append(resp.PLMNSupportList, plmn)
				}
			}

		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			if ie.Value.CriticalityDiagnostics != nil {
				resp.CriticalityDiagnostics = decodeCriticalityDiagnostics(ie.Value.CriticalityDiagnostics)
			}

		case ngapType.ProtocolIEIDUERetentionInformation:
			if ie.Value.UERetentionInformation != nil {
				v := int64(ie.Value.UERetentionInformation.Value)
				resp.UERetentionInformation = &v
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeNGSetupFailure(msg *ngapType.NGSetupFailure, resp *NGAPResponse) {
	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				resp.Cause = decodeCause(ie.Value.Cause)
			}

		case ngapType.ProtocolIEIDTimeToWait:
			if ie.Value.TimeToWait != nil {
				v := timeToWaitName(ie.Value.TimeToWait.Value)
				resp.TimeToWait = &v
			}

		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			if ie.Value.CriticalityDiagnostics != nil {
				resp.CriticalityDiagnostics = decodeCriticalityDiagnostics(ie.Value.CriticalityDiagnostics)
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}

func decodeCause(cause *ngapType.Cause) *CauseJSON {
	c := &CauseJSON{}
	switch cause.Present {
	case ngapType.CausePresentRadioNetwork:
		c.Group = "radio_network"
		c.Value = int(cause.RadioNetwork.Value)
	case ngapType.CausePresentTransport:
		c.Group = "transport"
		c.Value = int(cause.Transport.Value)
	case ngapType.CausePresentNas:
		c.Group = "nas"
		c.Value = int(cause.Nas.Value)
	case ngapType.CausePresentProtocol:
		c.Group = "protocol"
		c.Value = int(cause.Protocol.Value)
	case ngapType.CausePresentMisc:
		c.Group = "misc"
		c.Value = int(cause.Misc.Value)
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
		s := triggeringMessageName(cd.TriggeringMessage.Value)
		out.TriggeringMessage = &s
	}
	if cd.ProcedureCriticality != nil {
		s := criticalityName(cd.ProcedureCriticality.Value)
		out.ProcedureCriticality = &s
	}
	if cd.IEsCriticalityDiagnostics != nil {
		for _, item := range cd.IEsCriticalityDiagnostics.List {
			out.IEsCriticalityDiagnostics = append(out.IEsCriticalityDiagnostics, IECriticalityDiagnosticJSON{
				IECriticality: criticalityName(item.IECriticality.Value),
				IEID:          item.IEID.Value,
				TypeOfError:   typeOfErrorName(item.TypeOfError.Value),
			})
		}
	}
	return out
}

func triggeringMessageName(v aper.Enumerated) string {
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

func typeOfErrorName(v aper.Enumerated) string {
	switch v {
	case ngapType.TypeOfErrorPresentNotUnderstood:
		return "not_understood"
	case ngapType.TypeOfErrorPresentMissing:
		return "missing"
	default:
		return "unknown"
	}
}

func criticalityName(c aper.Enumerated) string {
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

func initiatingMessageName(msgType int, procedureCode int64) string {
	switch msgType {
	case ngapType.InitiatingMessagePresentDownlinkNASTransport:
		return "DownlinkNASTransport"
	case ngapType.InitiatingMessagePresentInitialContextSetupRequest:
		return "InitialContextSetupRequest"
	case ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest:
		return "PDUSessionResourceSetupRequest"
	case ngapType.InitiatingMessagePresentPDUSessionResourceReleaseCommand:
		return "PDUSessionResourceReleaseCommand"
	case ngapType.InitiatingMessagePresentPDUSessionResourceModifyRequest:
		return "PDUSessionResourceModifyRequest"
	case ngapType.InitiatingMessagePresentHandoverRequest:
		return "HandoverRequest"
	case ngapType.InitiatingMessagePresentUEContextReleaseCommand:
		return "UEContextReleaseCommand"
	case ngapType.InitiatingMessagePresentPaging:
		return "Paging"
	case ngapType.InitiatingMessagePresentDownlinkRANStatusTransfer:
		return "DownlinkRANStatusTransfer"
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
		return fmt.Sprintf("ProcedureCode(%d)", procedureCode)
	}
}

func successfulOutcomeName(msgType int, procedureCode int64) string {
	switch msgType {
	case ngapType.SuccessfulOutcomePresentNGSetupResponse:
		return "NGSetupResponse"
	case ngapType.SuccessfulOutcomePresentNGResetAcknowledge:
		return "NGResetAcknowledge"
	case ngapType.SuccessfulOutcomePresentHandoverCommand:
		return "HandoverCommand"
	case ngapType.SuccessfulOutcomePresentHandoverCancelAcknowledge:
		return "HandoverCancelAcknowledge"
	case ngapType.SuccessfulOutcomePresentInitialContextSetupResponse:
		return "InitialContextSetupResponse"
	case ngapType.SuccessfulOutcomePresentPDUSessionResourceSetupResponse:
		return "PDUSessionResourceSetupResponse"
	case ngapType.SuccessfulOutcomePresentUEContextReleaseComplete:
		return "UEContextReleaseComplete"
	case ngapType.SuccessfulOutcomePresentPathSwitchRequestAcknowledge:
		return "PathSwitchRequestAcknowledge"
	default:
		return fmt.Sprintf("ProcedureCode(%d)", procedureCode)
	}
}

func unsuccessfulOutcomeName(msgType int, procedureCode int64) string {
	switch msgType {
	case ngapType.UnsuccessfulOutcomePresentNGSetupFailure:
		return "NGSetupFailure"
	case ngapType.UnsuccessfulOutcomePresentHandoverPreparationFailure:
		return "HandoverPreparationFailure"
	case ngapType.UnsuccessfulOutcomePresentPathSwitchRequestFailure:
		return "PathSwitchRequestFailure"
	case ngapType.UnsuccessfulOutcomePresentInitialContextSetupFailure:
		return "InitialContextSetupFailure"
	default:
		return fmt.Sprintf("ProcedureCode(%d)", procedureCode)
	}
}

func timeToWaitName(t aper.Enumerated) string {
	switch t {
	case ngapType.TimeToWaitPresentV1s:
		return "v1s"
	case ngapType.TimeToWaitPresentV2s:
		return "v2s"
	case ngapType.TimeToWaitPresentV5s:
		return "v5s"
	case ngapType.TimeToWaitPresentV10s:
		return "v10s"
	case ngapType.TimeToWaitPresentV20s:
		return "v20s"
	case ngapType.TimeToWaitPresentV60s:
		return "v60s"
	default:
		return fmt.Sprintf("TimeToWait(%d)", t)
	}
}

func decodeUEContextReleaseCommand(msg *ngapType.UEContextReleaseCommand, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDUENGAPIDs:
			if ids := ie.Value.UENGAPIDs; ids != nil {
				switch ids.Present {
				case ngapType.UENGAPIDsPresentUENGAPIDPair:
					if pair := ids.UENGAPIDPair; pair != nil {
						amfID := pair.AMFUENGAPID.Value
						ranID := pair.RANUENGAPID.Value
						resp.AMFUENGAPID = &amfID
						resp.RANUENGAPID = &ranID
					}
				case ngapType.UENGAPIDsPresentAMFUENGAPID:
					if amf := ids.AMFUENGAPID; amf != nil {
						amfID := amf.Value
						resp.AMFUENGAPID = &amfID
					}
				}
			}
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				resp.Cause = decodeCause(ie.Value.Cause)
			}
		default:
			resp.UnknownIEs = append(resp.UnknownIEs, unknownIE(ie.Id.Value, ie.Criticality.Value, ie.Value))
		}
	}
}
