// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/ellanetworks/core/s1ap"
)

// Decode decodes a received S1AP PDU into its JSON form. Only the messages the
// server currently drives are mapped to typed fields; any other PDU is reported
// by its outcome and procedure code with the raw hex preserved.
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

		switch m.ProcedureCode {
		case s1ap.ProcDownlinkNASTransport:
			resp.MessageType = "DownlinkNASTransport"
			if err := decodeDownlinkNASTransport(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcInitialContextSetup:
			resp.MessageType = "InitialContextSetupRequest"
			if err := decodeInitialContextSetupRequest(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcERABSetup:
			resp.MessageType = "ERABSetupRequest"
			if err := decodeERABSetupRequest(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcERABRelease:
			resp.MessageType = "ERABReleaseCommand"
			if err := decodeERABReleaseCommand(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcERABModify:
			resp.MessageType = "ERABModifyRequest"
			if err := decodeERABModifyRequest(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcUEContextRelease:
			resp.MessageType = "UEContextReleaseCommand"
			if err := decodeUEContextReleaseCommand(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcErrorIndication:
			resp.MessageType = "ErrorIndication"
			if err := decodeErrorIndication(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcPaging:
			resp.MessageType = "Paging"
			if err := decodePaging(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcHandoverResourceAllocation:
			resp.MessageType = "HandoverRequest"
			if err := decodeHandoverRequest(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcMMEStatusTransfer:
			resp.MessageType = "MMEStatusTransfer"
			if err := decodeMMEStatusTransfer(m.Value, resp); err != nil {
				return nil, err
			}
		}
	case *s1ap.SuccessfulOutcome:
		resp.PDUType = "successful_outcome"
		resp.MessageType = procedureName(m.ProcedureCode)

		switch m.ProcedureCode {
		case s1ap.ProcS1Setup:
			resp.MessageType = "S1SetupResponse"

			sr, err := s1ap.ParseS1SetupResponse(m.Value)
			if err != nil {
				return nil, fmt.Errorf("parse S1SetupResponse: %w", err)
			}

			resp.S1SetupResponse = mapS1SetupResponse(sr)
		case s1ap.ProcPathSwitchRequest:
			resp.MessageType = "PathSwitchRequestAcknowledge"
			if err := decodePathSwitchRequestAcknowledge(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcReset:
			resp.MessageType = "ResetAcknowledge"
			if err := decodeResetAcknowledge(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcHandoverPreparation:
			resp.MessageType = "HandoverCommand"
			if err := decodeHandoverCommand(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcHandoverCancel:
			resp.MessageType = "HandoverCancelAcknowledge"
			if err := decodeHandoverCancelAcknowledge(m.Value, resp); err != nil {
				return nil, err
			}
		}
	case *s1ap.UnsuccessfulOutcome:
		resp.PDUType = "unsuccessful_outcome"
		resp.MessageType = procedureName(m.ProcedureCode)

		switch m.ProcedureCode {
		case s1ap.ProcS1Setup:
			resp.MessageType = "S1SetupFailure"

			sf, err := s1ap.ParseS1SetupFailure(m.Value)
			if err != nil {
				return nil, fmt.Errorf("parse S1SetupFailure: %w", err)
			}

			resp.S1SetupFailure = mapS1SetupFailure(sf)
		case s1ap.ProcPathSwitchRequest:
			resp.MessageType = "PathSwitchRequestFailure"
			if err := decodePathSwitchRequestFailure(m.Value, resp); err != nil {
				return nil, err
			}
		case s1ap.ProcHandoverPreparation:
			resp.MessageType = "HandoverPreparationFailure"
			if err := decodeHandoverPreparationFailure(m.Value, resp); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("s1ap: unexpected PDU type %T", pdu)
	}

	return resp, nil
}

func decodeDownlinkNASTransport(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseDownlinkNASTransport(value)
	if err != nil {
		return fmt.Errorf("parse DownlinkNASTransport: %w", err)
	}

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

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	resp.UEAggregateMaxBitRate = &UEAggregateMaxBitRateJSON{
		DL: int64(m.UEAggregateMaximumBitRate.DL),
		UL: int64(m.UEAggregateMaximumBitRate.UL),
	}

	for _, it := range m.ERABToBeSetup {
		item := ERABSetupItemJSON{ERABID: int(it.ERABID), GTPTEID: uint32(it.GTPTEID)}
		item.TransportLayerAddress = transportLayerIP(it.TransportLayerAddress)

		resp.ERABSetupItems = append(resp.ERABSetupItems, item)

		// The Attach Accept rides as the NAS-PDU of the default E-RAB item.
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

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	for _, it := range m.ERABToBeReleased {
		resp.ERABSetupItems = append(resp.ERABSetupItems, ERABSetupItemJSON{ERABID: int(it.ERABID)})
	}

	// The Deactivate EPS Bearer Context Request rides as the NAS-PDU.
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

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	for _, it := range m.ERABToBeModified {
		resp.ERABModifyItems = append(resp.ERABModifyItems, ERABModifyItemJSON{
			ERABID:           int(it.ERABID),
			QCI:              int(it.QoS.QCI),
			ARPPriorityLevel: int(it.QoS.ARP.PriorityLevel),
		})

		// The Modify EPS Bearer Context Request rides as the default bearer's NAS-PDU.
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

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	for _, it := range m.ERABToBeSetup {
		item := ERABSetupItemJSON{
			ERABID:                int(it.ERABID),
			GTPTEID:               uint32(it.GTPTEID),
			TransportLayerAddress: transportLayerIP(it.TransportLayerAddress),
		}
		resp.ERABSetupItems = append(resp.ERABSetupItems, item)

		// The Activate Default EPS Bearer Context Request rides as the E-RAB's NAS-PDU.
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

	// The release names the UE by its S1AP ID pair (or a bare MME ID); surface the
	// eNB ID when present so a waiter can match its UE.
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

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	resp.SecurityContext = &SecurityContextJSON{
		NextHopChainingCount: int(m.SecurityContext.NextHopChainingCount),
		NextHop:              hex.EncodeToString(m.SecurityContext.NextHopParameter[:]),
	}

	if m.UESecurityCapabilities != nil {
		resp.ReplayedUESecurityCapabilities = &UESecurityCapabilitiesJSON{
			EncryptionAlgorithms:          int(m.UESecurityCapabilities.EncryptionAlgorithms),
			IntegrityProtectionAlgorithms: int(m.UESecurityCapabilities.IntegrityProtectionAlgorithms),
		}
	}

	return nil
}

func decodePathSwitchRequestFailure(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParsePathSwitchRequestFailure(value)
	if err != nil {
		return fmt.Errorf("parse PathSwitchRequestFailure: %w", err)
	}

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	resp.Cause = &CauseJSON{Group: causeGroupName(m.Cause.Group), Value: m.Cause.Value}

	return nil
}

func decodeHandoverRequest(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseHandoverRequest(value)
	if err != nil {
		return fmt.Errorf("parse HandoverRequest: %w", err)
	}

	mme := int64(m.MMEUES1APID)
	resp.MMEUES1APID = &mme

	for _, it := range m.ERABToBeSetup {
		resp.ERABSetupItems = append(resp.ERABSetupItems, ERABSetupItemJSON{
			ERABID:                int(it.ERABID),
			GTPTEID:               uint32(it.GTPTEID),
			TransportLayerAddress: transportLayerIP(it.TransportLayerAddress),
		})
	}

	resp.SecurityContext = &SecurityContextJSON{
		NextHopChainingCount: int(m.SecurityContext.NextHopChainingCount),
		NextHop:              hex.EncodeToString(m.SecurityContext.NextHopParameter[:]),
	}

	return nil
}

func decodeHandoverCommand(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseHandoverCommand(value)
	if err != nil {
		return fmt.Errorf("parse HandoverCommand: %w", err)
	}

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

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))
	resp.Cause = &CauseJSON{Group: causeGroupName(m.Cause.Group), Value: m.Cause.Value}

	return nil
}

func decodeHandoverCancelAcknowledge(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseHandoverCancelAcknowledge(value)
	if err != nil {
		return fmt.Errorf("parse HandoverCancelAcknowledge: %w", err)
	}

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	return nil
}

func decodeMMEStatusTransfer(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseMMEStatusTransfer(value)
	if err != nil {
		return fmt.Errorf("parse MMEStatusTransfer: %w", err)
	}

	setUEIDs(resp, int64(m.MMEUES1APID), int64(m.ENBUES1APID))

	return nil
}

func decodeErrorIndication(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParseErrorIndication(value)
	if err != nil {
		return fmt.Errorf("parse ErrorIndication: %w", err)
	}

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

	return nil
}

func decodePaging(value []byte, resp *S1APResponse) error {
	m, err := s1ap.ParsePaging(value)
	if err != nil {
		return fmt.Errorf("parse Paging: %w", err)
	}

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

// transportLayerIP renders an S1AP Transport Layer Address (TS 36.414): 4 octets
// for IPv4, 16 for IPv6, or 20 for a dual-stack address carrying the IPv4
// followed by the IPv6. The IPv4 is preferred when present, since the user-plane
// data path is IPv4.
func transportLayerIP(b []byte) string {
	switch len(b) {
	case 4, 20:
		return net.IP(b[:4]).String()
	case 16:
		return net.IP(b).String()
	default:
		return ""
	}
}

func setUEIDs(resp *S1APResponse, mme, enb int64) {
	resp.MMEUES1APID = &mme
	resp.ENBUES1APID = &enb
}

func mapS1SetupResponse(sr *s1ap.S1SetupResponse) *S1SetupResponseJSON {
	out := &S1SetupResponseJSON{
		MMEName:             sr.MMEName,
		RelativeMMECapacity: int(sr.RelativeMMECapacity),
	}

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

		out.ServedGUMMEIs = append(out.ServedGUMMEIs, g)
	}

	return out
}

func mapS1SetupFailure(sf *s1ap.S1SetupFailure) *S1SetupFailureJSON {
	out := &S1SetupFailureJSON{
		Cause: CauseJSON{Group: causeGroupName(sf.Cause.Group), Value: sf.Cause.Value},
	}

	if sf.TimeToWait != nil {
		ttw := timeToWaitName(*sf.TimeToWait)
		out.TimeToWait = &ttw
	}

	return out
}

// procedureName maps an S1AP procedure code to a stable message name so
// unexpected downlinks get a usable message_type to await on and a readable JSON
// label. For procedures with distinct outcomes (e.g. S1 Setup) the caller
// refines the name per outcome.
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
