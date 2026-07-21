// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/ellanetworks/core/s1ap"
)

func Decode(data []byte) (*S1APResponse, error) {
	pdu, err := s1ap.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("s1ap unmarshal: %w", err)
	}

	resp := &S1APResponse{RawHex: hex.EncodeToString(data)}

	switch m := pdu.(type) {
	case *s1ap.InitiatingMessage:
		resp.PDUType = "initiating_message"
		resp.MessageType = procedureName(m.ProcedureCode)
		if err := decodeInitiatingMessage(m, resp); err != nil {
			return nil, err
		}
	case *s1ap.SuccessfulOutcome:
		resp.PDUType = "successful_outcome"
		resp.MessageType = procedureName(m.ProcedureCode)
		if err := decodeSuccessfulOutcome(m, resp); err != nil {
			return nil, err
		}
	case *s1ap.UnsuccessfulOutcome:
		resp.PDUType = "unsuccessful_outcome"
		resp.MessageType = procedureName(m.ProcedureCode)
		if err := decodeUnsuccessfulOutcome(m, resp); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("s1ap: unexpected PDU type %T", pdu)
	}

	return resp, nil
}

func decodeInitiatingMessage(m *s1ap.InitiatingMessage, resp *S1APResponse) error {
	switch m.ProcedureCode {
	case s1ap.ProcDownlinkNASTransport:
		resp.MessageType = "DownlinkNASTransport"
		if err := decodeDownlinkNASTransport(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcInitialContextSetup:
		resp.MessageType = "InitialContextSetupRequest"
		if err := decodeInitialContextSetupRequest(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcERABSetup:
		resp.MessageType = "ERABSetupRequest"
		if err := decodeERABSetupRequest(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcERABRelease:
		resp.MessageType = "ERABReleaseCommand"
		if err := decodeERABReleaseCommand(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcERABModify:
		resp.MessageType = "ERABModifyRequest"
		if err := decodeERABModifyRequest(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcUEContextRelease:
		resp.MessageType = "UEContextReleaseCommand"
		if err := decodeUEContextReleaseCommand(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcErrorIndication:
		resp.MessageType = "ErrorIndication"
		if err := decodeErrorIndication(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcPaging:
		resp.MessageType = "Paging"
		if err := decodePaging(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcHandoverResourceAllocation:
		resp.MessageType = "HandoverRequest"
		if err := decodeHandoverRequest(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcMMEStatusTransfer:
		resp.MessageType = "MMEStatusTransfer"
		if err := decodeMMEStatusTransfer(m.Value, resp); err != nil {
			return err
		}
	}

	return nil
}

func decodeSuccessfulOutcome(m *s1ap.SuccessfulOutcome, resp *S1APResponse) error {
	switch m.ProcedureCode {
	case s1ap.ProcS1Setup:
		resp.MessageType = "S1SetupResponse"

		sr, err := s1ap.ParseS1SetupResponse(m.Value)
		if err != nil {
			return fmt.Errorf("parse S1SetupResponse: %w", err)
		}

		setUnknownIEs(resp, sr)

		decodeS1SetupResponse(sr, resp)
	case s1ap.ProcPathSwitchRequest:
		resp.MessageType = "PathSwitchRequestAcknowledge"
		if err := decodePathSwitchRequestAcknowledge(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcReset:
		resp.MessageType = "ResetAcknowledge"
		if err := decodeResetAcknowledge(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcHandoverPreparation:
		resp.MessageType = "HandoverCommand"
		if err := decodeHandoverCommand(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcHandoverCancel:
		resp.MessageType = "HandoverCancelAcknowledge"
		if err := decodeHandoverCancelAcknowledge(m.Value, resp); err != nil {
			return err
		}
	}

	return nil
}

func decodeUnsuccessfulOutcome(m *s1ap.UnsuccessfulOutcome, resp *S1APResponse) error {
	switch m.ProcedureCode {
	case s1ap.ProcS1Setup:
		resp.MessageType = "S1SetupFailure"

		sf, err := s1ap.ParseS1SetupFailure(m.Value)
		if err != nil {
			return fmt.Errorf("parse S1SetupFailure: %w", err)
		}

		setUnknownIEs(resp, sf)

		decodeS1SetupFailure(sf, resp)

		if sf.CriticalityDiagnostics != nil {
			resp.CriticalityDiagnostics = decodeCriticalityDiagnostics(sf.CriticalityDiagnostics)
		}
	case s1ap.ProcPathSwitchRequest:
		resp.MessageType = "PathSwitchRequestFailure"
		if err := decodePathSwitchRequestFailure(m.Value, resp); err != nil {
			return err
		}
	case s1ap.ProcHandoverPreparation:
		resp.MessageType = "HandoverPreparationFailure"
		if err := decodeHandoverPreparationFailure(m.Value, resp); err != nil {
			return err
		}
	}

	return nil
}

func decodeDownlinkNASTransport(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseDownlinkNASTransport(value)
	if err != nil {
		return fmt.Errorf("parse DownlinkNASTransport: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	nas := hex.EncodeToString(m.NASPDU)
	resp.NASPDU = &nas

	return nil
}

func decodeInitialContextSetupRequest(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseInitialContextSetupRequest(value)
	if err != nil {
		return fmt.Errorf("parse InitialContextSetupRequest: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	resp.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
		DL: int64(m.UEAggregateMaximumBitRate.DL),
		UL: int64(m.UEAggregateMaximumBitRate.UL),
	}

	for _, it := range m.ERABToBeSetup {
		item := ERABSetupItemJSON{ERABID: int(it.ERABID), GTPTEID: uint32(it.GTPTEID)}
		item.TransportLayerAddress, item.TransportLayerAddressIPv6 = transportLayerIPs(it.TransportLayerAddress)

		resp.ERABSetupItems = append(resp.ERABSetupItems, item)

		if len(it.NASPDU) > 0 && resp.NASPDU == nil {
			nas := hex.EncodeToString(it.NASPDU)
			resp.NASPDU = &nas
		}
	}

	if len(m.UERadioCapability) > 0 {
		cap := hex.EncodeToString(m.UERadioCapability)
		resp.UERadioCapability = &cap
	}

	return nil
}

func decodeERABReleaseCommand(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseERABReleaseCommand(value)
	if err != nil {
		return fmt.Errorf("parse ERABReleaseCommand: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	for _, it := range m.ERABToBeReleased {
		resp.ERABSetupItems = append(resp.ERABSetupItems, ERABSetupItemJSON{ERABID: int(it.ERABID)})
	}

	if len(m.NASPDU) > 0 {
		nas := hex.EncodeToString([]byte(m.NASPDU))
		resp.NASPDU = &nas
	}

	return nil
}

func decodeERABModifyRequest(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseERABModifyRequest(value)
	if err != nil {
		return fmt.Errorf("parse ERABModifyRequest: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	for _, it := range m.ERABToBeModified {
		resp.ERABModifyItems = append(resp.ERABModifyItems, ERABModifyItemJSON{
			ERABID:           int(it.ERABID),
			QCI:              int(it.QoS.QCI),
			ARPPriorityLevel: int(it.QoS.ARP.PriorityLevel),
		})

		if len(it.NASPDU) > 0 && resp.NASPDU == nil {
			nas := hex.EncodeToString([]byte(it.NASPDU))
			resp.NASPDU = &nas
		}
	}

	return nil
}

func decodeResetAcknowledge(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseResetAcknowledge(value)
	if err != nil {
		return fmt.Errorf("parse ResetAcknowledge: %w", err)
	}

	setUnknownIEs(resp, m)

	for _, c := range m.ConnectionList {
		item := ResetConnectionJSON{}
		if c.MMEUES1APID != nil {
			v := int64(*c.MMEUES1APID)
			item.MMEUES1APID = &v
		}

		if c.ENBUES1APID != nil {
			v := int64(*c.ENBUES1APID)
			item.ENBUES1APID = &v
		}

		resp.ResetConnections = append(resp.ResetConnections, item)
	}

	return nil
}

func decodeERABSetupRequest(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseERABSetupRequest(value)
	if err != nil {
		return fmt.Errorf("parse ERABSetupRequest: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	for _, it := range m.ERABToBeSetup {
		item := ERABSetupItemJSON{ERABID: int(it.ERABID), GTPTEID: uint32(it.GTPTEID)}
		item.TransportLayerAddress, item.TransportLayerAddressIPv6 = transportLayerIPs(it.TransportLayerAddress)
		resp.ERABSetupItems = append(resp.ERABSetupItems, item)

		if len(it.NASPDU) > 0 && resp.NASPDU == nil {
			nas := hex.EncodeToString([]byte(it.NASPDU))
			resp.NASPDU = &nas
		}
	}

	return nil
}

func decodeUEContextReleaseCommand(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseUEContextReleaseCommand(value)
	if err != nil {
		return fmt.Errorf("parse UEContextReleaseCommand: %w", err)
	}

	setUnknownIEs(resp, m)

	mme := int64(m.UES1APIDs.MMEUES1APID)
	resp.MMEUES1APID = &mme

	if m.UES1APIDs.Pair {
		enb := int64(m.UES1APIDs.ENBUES1APID)
		resp.ENBUES1APID = &enb
	}

	resp.Cause = &CauseJSON{Group: causeGroupName(m.Cause.Group), Value: m.Cause.Value}

	return nil
}

func decodePathSwitchRequestAcknowledge(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParsePathSwitchRequestAcknowledge(value)
	if err != nil {
		return fmt.Errorf("parse PathSwitchRequestAcknowledge: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	resp.SecurityContext = &SecurityContextJSON{
		NextHopChainingCount: int(m.SecurityContext.NextHopChainingCount),
		NextHop:              hex.EncodeToString(m.SecurityContext.NextHopParameter[:]),
	}

	if m.UESecurityCapabilities != nil {
		resp.ReplayedUESecurityCapabilities = &UESecurityCapabilitiesJSON{
			EncryptionAlgorithms:          secCapHex(m.UESecurityCapabilities.EncryptionAlgorithms),
			IntegrityProtectionAlgorithms: secCapHex(m.UESecurityCapabilities.IntegrityProtectionAlgorithms),
		}
	}

	return nil
}

func decodePathSwitchRequestFailure(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParsePathSwitchRequestFailure(value)
	if err != nil {
		return fmt.Errorf("parse PathSwitchRequestFailure: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	resp.Cause = &CauseJSON{Group: causeGroupName(m.Cause.Group), Value: m.Cause.Value}

	return nil
}

func decodeHandoverRequest(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseHandoverRequest(value)
	if err != nil {
		return fmt.Errorf("parse HandoverRequest: %w", err)
	}

	setUnknownIEs(resp, m)

	mme := int64(m.MMEUES1APID)
	resp.MMEUES1APID = &mme

	for _, it := range m.ERABToBeSetup {
		item := ERABSetupItemJSON{ERABID: int(it.ERABID), GTPTEID: uint32(it.GTPTEID)}
		item.TransportLayerAddress, item.TransportLayerAddressIPv6 = transportLayerIPs(it.TransportLayerAddress)
		resp.ERABSetupItems = append(resp.ERABSetupItems, item)
	}

	resp.SecurityContext = &SecurityContextJSON{
		NextHopChainingCount: int(m.SecurityContext.NextHopChainingCount),
		NextHop:              hex.EncodeToString(m.SecurityContext.NextHopParameter[:]),
	}

	resp.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
		DL: int64(m.UEAMBR.DL),
		UL: int64(m.UEAMBR.UL),
	}

	resp.UESecurityCapabilities = &UESecurityCapabilitiesJSON{
		EncryptionAlgorithms:          secCapHex(m.UESecurityCapabilities.EncryptionAlgorithms),
		IntegrityProtectionAlgorithms: secCapHex(m.UESecurityCapabilities.IntegrityProtectionAlgorithms),
	}

	if len(m.SourceToTarget) > 0 {
		c := hex.EncodeToString(m.SourceToTarget)
		resp.SourceToTargetContainer = &c
	}

	return nil
}

func decodeHandoverCommand(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseHandoverCommand(value)
	if err != nil {
		return fmt.Errorf("parse HandoverCommand: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	for _, it := range m.ERABToRelease {
		resp.ReleasedERABs = append(resp.ReleasedERABs, int(it.ERABID))
	}

	return nil
}

func decodeHandoverPreparationFailure(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseHandoverPreparationFailure(value)
	if err != nil {
		return fmt.Errorf("parse HandoverPreparationFailure: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	resp.Cause = &CauseJSON{Group: causeGroupName(m.Cause.Group), Value: m.Cause.Value}

	return nil
}

func decodeHandoverCancelAcknowledge(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseHandoverCancelAcknowledge(value)
	if err != nil {
		return fmt.Errorf("parse HandoverCancelAcknowledge: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	return nil
}

func decodeMMEStatusTransfer(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseMMEStatusTransfer(value)
	if err != nil {
		return fmt.Errorf("parse MMEStatusTransfer: %w", err)
	}

	setUnknownIEs(resp, m)

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	resp.StatusTransferContainer = hex.EncodeToString(m.Container)

	return nil
}

func decodeErrorIndication(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseErrorIndication(value)
	if err != nil {
		return fmt.Errorf("parse ErrorIndication: %w", err)
	}

	setUnknownIEs(resp, m)

	if m.MMEUES1APID != nil {
		v := int64(*m.MMEUES1APID)
		resp.MMEUES1APID = &v
	}

	if m.ENBUES1APID != nil {
		v := int64(*m.ENBUES1APID)
		resp.ENBUES1APID = &v
	}

	if m.Cause != nil {
		resp.Cause = &CauseJSON{Group: causeGroupName(m.Cause.Group), Value: m.Cause.Value}
	}

	if m.CriticalityDiagnostics != nil {
		resp.CriticalityDiagnostics = decodeCriticalityDiagnostics(m.CriticalityDiagnostics)
	}

	return nil
}

func decodePaging(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParsePaging(value)
	if err != nil {
		return fmt.Errorf("parse Paging: %w", err)
	}

	setUnknownIEs(resp, m)

	resp.Paging = &PagingJSON{
		MMEC:                 m.STMSI.MMEC,
		MTMSI:                m.STMSI.MTMSI,
		UEIdentityIndexValue: m.UEIdentityIndexValue,
		CNDomain:             cnDomainName(m.CNDomain),
	}

	return nil
}

func cnDomainName(d s1ap.CNDomain) string {
	switch d {
	case s1ap.CNDomainPS:
		return "ps"
	case s1ap.CNDomainCS:
		return "cs"
	default:
		return fmt.Sprintf("CNDomain(%d)", d)
	}
}

// TransportLayerAddress: 32-bit IPv4, 128-bit IPv6, or 160-bit carrying the IPv4 in the first 32 bits (TS 36.414 §5.3).
func transportLayerIPs(b []byte) (ipv4, ipv6 string) {
	switch len(b) {
	case 4:
		return net.IP(b).String(), ""
	case 16:
		return "", net.IP(b).String()
	case 20:
		return net.IP(b[:4]).String(), net.IP(b[4:20]).String()
	default:
		return "", ""
	}
}

func setUEIDs(resp *S1APResponse, mme, enb int64) {
	resp.MMEUES1APID = &mme
	resp.ENBUES1APID = &enb
}

type unknownIECarrier interface {
	UnknownIEs() []s1ap.RawIE
}

func setUnknownIEs(resp *S1APResponse, m unknownIECarrier) {
	for _, ie := range m.UnknownIEs() {
		resp.UnknownIEs = append(resp.UnknownIEs, UnknownIEJSON{
			ID:          int64(ie.ID),
			Criticality: ie.Criticality.String(),
			ValueHex:    hex.EncodeToString(ie.Value),
		})
	}
}

func decodeS1SetupResponse(sr *s1ap.S1SetupResponse, resp *S1APResponse) {
	if sr.MMEName != "" {
		name := sr.MMEName
		resp.MMEName = &name
	}

	capacity := int64(sr.RelativeMMECapacity)
	resp.RelativeMMECapacity = &capacity

	for _, it := range sr.ServedGUMMEIs {
		g := ServedGUMMEIJSON{}

		for _, p := range it.ServedPLMNs {
			g.ServedPLMNs = append(g.ServedPLMNs, hex.EncodeToString(p[:]))
		}

		for _, id := range it.ServedGroupIDs {
			g.ServedGroupIDs = append(g.ServedGroupIDs, hex.EncodeToString(id[:]))
		}

		for _, c := range it.ServedMMECs {
			g.ServedMMECs = append(g.ServedMMECs, hex.EncodeToString([]byte{byte(c)}))
		}

		resp.ServedGUMMEIs = append(resp.ServedGUMMEIs, g)
	}
}

func decodeS1SetupFailure(sf *s1ap.S1SetupFailure, resp *S1APResponse) {
	resp.Cause = &CauseJSON{Group: causeGroupName(sf.Cause.Group), Value: sf.Cause.Value}

	if sf.TimeToWait != nil {
		ttw := timeToWaitName(*sf.TimeToWait)
		resp.TimeToWait = &ttw
	}
}

func procedureName(pc s1ap.ProcedureCode) string {
	switch pc {
	case s1ap.ProcS1Setup:
		return "S1Setup"
	case s1ap.ProcErrorIndication:
		return "ErrorIndication"
	case s1ap.ProcReset:
		return "Reset"
	case s1ap.ProcInitialContextSetup:
		return "InitialContextSetup"
	case s1ap.ProcDownlinkNASTransport:
		return "DownlinkNASTransport"
	case s1ap.ProcUEContextRelease:
		return "UEContextRelease"
	case s1ap.ProcUEContextReleaseRequest:
		return "UEContextReleaseRequest"
	case s1ap.ProcPaging:
		return "Paging"
	case s1ap.ProcInitialUEMessage:
		return "InitialUEMessage"
	case s1ap.ProcUplinkNASTransport:
		return "UplinkNASTransport"
	case s1ap.ProcPathSwitchRequest:
		return "PathSwitchRequest"
	case s1ap.ProcERABSetup:
		return "ERABSetup"
	case s1ap.ProcERABRelease:
		return "ERABRelease"
	case s1ap.ProcHandoverPreparation:
		return "HandoverPreparation"
	case s1ap.ProcHandoverResourceAllocation:
		return "HandoverResourceAllocation"
	case s1ap.ProcHandoverNotification:
		return "HandoverNotify"
	case s1ap.ProcHandoverCancel:
		return "HandoverCancel"
	case s1ap.ProcENBStatusTransfer:
		return "ENBStatusTransfer"
	case s1ap.ProcMMEStatusTransfer:
		return "MMEStatusTransfer"
	default:
		return fmt.Sprintf("ProcedureCode(%d)", pc)
	}
}

func decodeCriticalityDiagnostics(cd *s1ap.CriticalityDiagnostics) *CriticalityDiagnosticsJSON {
	out := &CriticalityDiagnosticsJSON{}

	if cd.ProcedureCode != nil {
		v := int64(*cd.ProcedureCode)
		out.ProcedureCode = &v
	}

	if cd.TriggeringMessage != nil {
		s := triggeringMessageName(*cd.TriggeringMessage)
		out.TriggeringMessage = &s
	}

	if cd.ProcedureCriticality != nil {
		s := cd.ProcedureCriticality.String()
		out.ProcedureCriticality = &s
	}

	for _, item := range cd.IEsCriticalityDiagnostics {
		out.IEsCriticalityDiagnostics = append(out.IEsCriticalityDiagnostics, IECriticalityDiagnosticJSON{
			IECriticality: item.IECriticality.String(),
			IEID:          int64(item.IEID),
			TypeOfError:   typeOfErrorName(item.TypeOfError),
		})
	}

	return out
}

func triggeringMessageName(v s1ap.TriggeringMessage) string {
	switch v {
	case s1ap.TriggeringInitiatingMessage:
		return "initiating_message"
	case s1ap.TriggeringSuccessfulOutcome:
		return "successful_outcome"
	case s1ap.TriggeringUnsuccessfulOutcome:
		return "unsuccessful_outcome"
	default:
		return "unknown"
	}
}

func typeOfErrorName(v s1ap.TypeOfError) string {
	switch v {
	case s1ap.TypeOfErrorNotUnderstood:
		return "not_understood"
	case s1ap.TypeOfErrorMissing:
		return "missing"
	default:
		return "unknown"
	}
}

func secCapHex(algorithms uint16) string {
	return fmt.Sprintf("%04x", algorithms)
}

func causeGroupName(g s1ap.CauseGroup) string {
	switch g {
	case s1ap.CauseGroupRadioNetwork:
		return "radio_network"
	case s1ap.CauseGroupTransport:
		return "transport"
	case s1ap.CauseGroupNAS:
		return "nas"
	case s1ap.CauseGroupProtocol:
		return "protocol"
	case s1ap.CauseGroupMisc:
		return "misc"
	default:
		return fmt.Sprintf("CauseGroup(%d)", g)
	}
}

func timeToWaitName(t s1ap.TimeToWait) string {
	switch t {
	case s1ap.TimeToWaitV1s:
		return "v1s"
	case s1ap.TimeToWaitV2s:
		return "v2s"
	case s1ap.TimeToWaitV5s:
		return "v5s"
	case s1ap.TimeToWaitV10s:
		return "v10s"
	case s1ap.TimeToWaitV20s:
		return "v20s"
	case s1ap.TimeToWaitV60s:
		return "v60s"
	default:
		return fmt.Sprintf("TimeToWait(%d)", t)
	}
}
