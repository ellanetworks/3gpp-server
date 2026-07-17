// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
		decoded := IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value)}

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
		case ngapType.ProtocolIEIDUESecurityCapabilities:
			if ie.Value.UESecurityCapabilities != nil {
				decoded.UESecurityCapabilities = decodeUESecurityCapabilities(ie.Value.UESecurityCapabilities)
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSwitchedList:
			if ie.Value.PDUSessionResourceSwitchedList != nil {
				for _, item := range ie.Value.PDUSessionResourceSwitchedList.List {
					decoded.PDUSessionIDs = append(decoded.PDUSessionIDs, item.PDUSessionID.Value)
				}
			}
		case ngapType.ProtocolIEIDPDUSessionResourceReleasedListPSAck:
			if ie.Value.PDUSessionResourceReleasedListPSAck != nil {
				for _, item := range ie.Value.PDUSessionResourceReleasedListPSAck.List {
					decoded.ReleasePDUSessionIDs = append(decoded.ReleasePDUSessionIDs, item.PDUSessionID.Value)
				}
			}
		case ngapType.ProtocolIEIDSecurityContext:
			if ie.Value.SecurityContext != nil {
				v := ie.Value.SecurityContext.NextHopChainingCount.Value
				decoded.NextHopChainingCount = &v
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
	}
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
		decoded := IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value)}

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
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
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
				resp.IEs = append(resp.IEs, IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value), AmfUeNgapID: &v})
			}
		case ngapType.ProtocolIEIDRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				v := ie.Value.RANUENGAPID.Value
				resp.IEs = append(resp.IEs, IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value), RanUeNgapID: &v})
			}
		case ngapType.ProtocolIEIDPDUSessionResourceHandoverList:
			if list := ie.Value.PDUSessionResourceHandoverList; list != nil {
				ids := make([]int64, 0, len(list.List))
				for _, item := range list.List {
					ids = append(ids, item.PDUSessionID.Value)
				}
				resp.IEs = append(resp.IEs, IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value), PDUSessionIDs: ids})
			}
		case ngapType.ProtocolIEIDPDUSessionResourceToReleaseListHOCmd:
			if list := ie.Value.PDUSessionResourceToReleaseListHOCmd; list != nil {
				ids := make([]int64, 0, len(list.List))
				for _, item := range list.List {
					ids = append(ids, item.PDUSessionID.Value)
				}
				resp.IEs = append(resp.IEs, IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value), ReleasePDUSessionIDs: ids})
			}
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
			continue
		}

		for _, item := range ie.Value.UEAssociatedLogicalNGConnectionList.List {
			decoded := IE{
				ID:          ie.Id.Value,
				Criticality: criticalityName(ie.Criticality.Value),
			}

			if item.AMFUENGAPID != nil {
				v := item.AMFUENGAPID.Value
				decoded.AmfUeNgapID = &v
			}

			if item.RANUENGAPID != nil {
				v := item.RANUENGAPID.Value
				decoded.RanUeNgapID = &v
			}

			resp.IEs = append(resp.IEs, decoded)
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
		decoded := IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value)}

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
		case ngapType.ProtocolIEIDPDUSessionResourceReleasedListPSFail:
			if ie.Value.PDUSessionResourceReleasedListPSFail != nil {
				for _, item := range ie.Value.PDUSessionResourceReleasedListPSFail.List {
					decoded.ReleasePDUSessionIDs = append(decoded.ReleasePDUSessionIDs, item.PDUSessionID.Value)
				}
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodeHandoverPreparationFailure(msg *ngapType.HandoverPreparationFailure, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value)}

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
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				decoded.Cause = decodeCause(ie.Value.Cause)
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodePDUSessionResourceModifyRequest(msg *ngapType.PDUSessionResourceModifyRequest, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityName(ie.Criticality.Value),
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
		case ngapType.ProtocolIEIDPDUSessionResourceModifyListModReq:
			if ie.Value.PDUSessionResourceModifyListModReq != nil {
				for i := range ie.Value.PDUSessionResourceModifyListModReq.List {
					if nasPDU := ie.Value.PDUSessionResourceModifyListModReq.List[i].NASPDU; nasPDU != nil && decoded.NasPDU == nil {
						s := hex.EncodeToString(nasPDU.Value)
						decoded.NasPDU = &s
					}
				}
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

// Re-encodes an unmodeled IE's CHOICE value so its octets survive; nil when aper discarded them (id absent from the message CHOICE).
func unmodeledIEValue(v any) json.RawMessage {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Struct || rv.NumField() == 0 {
		return nil
	}

	present := int(rv.Field(0).Int())
	if present <= 0 || present >= rv.NumField() {
		return nil
	}

	alt := rv.Field(present)
	if alt.Kind() == reflect.Pointer && alt.IsNil() {
		return nil
	}

	octets, err := aper.MarshalWithParams(alt.Interface(), rv.Type().Field(present).Tag.Get("aper"))
	if err != nil {
		return nil
	}

	out, err := json.Marshal(hex.EncodeToString(octets))
	if err != nil {
		return nil
	}

	return out
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
		decoded := IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value)}

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
		case ngapType.ProtocolIEIDRANStatusTransferTransparentContainer:
			if ie.Value.RANStatusTransferTransparentContainer != nil {
				decoded.RANStatusTransfer = decodeRANStatusTransferContainer(ie.Value.RANStatusTransferTransparentContainer)
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
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
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityName(ie.Criticality.Value),
		}

		if ie.Id.Value == ngapType.ProtocolIEIDUEPagingIdentity &&
			ie.Value.UEPagingIdentity != nil && ie.Value.UEPagingIdentity.FiveGSTMSI != nil {
			decoded.FiveGSTMSI = decodeFiveGSTMSI(ie.Value.UEPagingIdentity.FiveGSTMSI)
		} else {
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
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
		decoded := IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value)}

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
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				decoded.Cause = decodeCause(ie.Value.Cause)
			}
		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			if ie.Value.CriticalityDiagnostics != nil {
				decoded.CriticalityDiagnostics = decodeCriticalityDiagnostics(ie.Value.CriticalityDiagnostics)
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
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
				resp.IEs = append(resp.IEs, IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value), AmfUeNgapID: &v})
			}
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListHOReq:
			if list := ie.Value.PDUSessionResourceSetupListHOReq; list != nil {
				ids := make([]int64, 0, len(list.List))
				for _, item := range list.List {
					ids = append(ids, item.PDUSessionID.Value)
				}
				resp.IEs = append(resp.IEs, IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value), PDUSessionIDs: ids})
			}
		case ngapType.ProtocolIEIDUEAggregateMaximumBitRate:
			if ambr := ie.Value.UEAggregateMaximumBitRate; ambr != nil {
				resp.IEs = append(resp.IEs, IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value),
					UEAggregateMaxBitRate: &UEAggregateMaxBitRateJSON{
						DL: ambr.UEAggregateMaximumBitRateDL.Value,
						UL: ambr.UEAggregateMaximumBitRateUL.Value,
					}})
			}
		case ngapType.ProtocolIEIDSecurityContext:
			if sc := ie.Value.SecurityContext; sc != nil {
				ncc := sc.NextHopChainingCount.Value
				resp.IEs = append(resp.IEs, IE{ID: ie.Id.Value, Criticality: criticalityName(ie.Criticality.Value), NextHopChainingCount: &ncc})
			}
		}
	}
}

func decodePDUSessionResourceReleaseCommand(msg *ngapType.PDUSessionResourceReleaseCommand, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityName(ie.Criticality.Value),
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
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodeInitialContextSetupRequest(msg *ngapType.InitialContextSetupRequest, resp *NGAPResponse) {
	if msg == nil {
		return
	}

	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityName(ie.Criticality.Value),
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
		case ngapType.ProtocolIEIDUERadioCapability:
			if ie.Value.UERadioCapability != nil {
				s := hex.EncodeToString(ie.Value.UERadioCapability.Value)
				decoded.UERadioCapability = &s
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
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
			Criticality: criticalityName(ie.Criticality.Value),
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
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
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
			Criticality: criticalityName(ie.Criticality.Value),
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
					if item.PDUSessionNASPDU != nil && decoded.NasPDU == nil {
						s := hex.EncodeToString(item.PDUSessionNASPDU.Value)
						decoded.NasPDU = &s
					}

					setupItem := PDUSessionSetupItemJSON{PDUSessionID: item.PDUSessionID.Value}
					if teid, ipv4, ipv6, ok := decodeULTunnel(item.PDUSessionResourceSetupRequestTransfer); ok {
						setupItem.ULTeid = teid
						setupItem.UPFN3IP = ipv4
						setupItem.UPFN3IPv6 = ipv6
					}

					decoded.PDUSessionSetupItems = append(decoded.PDUSessionSetupItems, setupItem)
				}
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodeNGSetupResponse(msg *ngapType.NGSetupResponse, resp *NGAPResponse) {
	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityName(ie.Criticality.Value),
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
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}

func decodeNGSetupFailure(msg *ngapType.NGSetupFailure, resp *NGAPResponse) {
	for _, ie := range msg.ProtocolIEs.List {
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityName(ie.Criticality.Value),
		}

		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				decoded.Cause = decodeCause(ie.Value.Cause)
			}

		case ngapType.ProtocolIEIDTimeToWait:
			if ie.Value.TimeToWait != nil {
				v := timeToWaitName(ie.Value.TimeToWait.Value)
				decoded.TimeToWait = &v
			}

		case ngapType.ProtocolIEIDCriticalityDiagnostics:
			if ie.Value.CriticalityDiagnostics != nil {
				decoded.CriticalityDiagnostics = decodeCriticalityDiagnostics(ie.Value.CriticalityDiagnostics)
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
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
		decoded := IE{
			ID:          ie.Id.Value,
			Criticality: criticalityName(ie.Criticality.Value),
		}

		switch ie.Id.Value {
		case ngapType.ProtocolIEIDUENGAPIDs:
			if ids := ie.Value.UENGAPIDs; ids != nil {
				switch ids.Present {
				case ngapType.UENGAPIDsPresentUENGAPIDPair:
					if pair := ids.UENGAPIDPair; pair != nil {
						amfID := pair.AMFUENGAPID.Value
						ranID := pair.RANUENGAPID.Value
						decoded.AmfUeNgapID = &amfID
						decoded.RanUeNgapID = &ranID
					}
				case ngapType.UENGAPIDsPresentAMFUENGAPID:
					if amf := ids.AMFUENGAPID; amf != nil {
						amfID := amf.Value
						decoded.AmfUeNgapID = &amfID
					}
				}
			}
		case ngapType.ProtocolIEIDCause:
			if ie.Value.Cause != nil {
				decoded.Cause = decodeCause(ie.Value.Cause)
			}
		default:
			decoded.Value = unmodeledIEValue(ie.Value)
		}

		resp.IEs = append(resp.IEs, decoded)
	}
}
