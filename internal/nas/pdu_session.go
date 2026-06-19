// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"bytes"
	"encoding/hex"
	"fmt"

	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

type PDUSessionEstablishmentRequestOpts struct {
	PDUSessionID   uint8
	PDUSessionType uint8
	PTI            uint8
	AlwaysOn       bool
	DNN            string
	SST            int32
	SD             string
}

func BuildPDUSessionEstablishmentRequest(opts *PDUSessionEstablishmentRequestOpts) ([]byte, error) {
	m := gonas.NewMessage()
	m.GsmMessage = gonas.NewGsmMessage()
	m.GsmHeader.SetMessageType(gonas.MsgTypePDUSessionEstablishmentRequest)

	req := nasMessage.NewPDUSessionEstablishmentRequest(0)
	req.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	req.SetMessageType(gonas.MsgTypePDUSessionEstablishmentRequest)
	req.SetPDUSessionID(opts.PDUSessionID)
	req.SetPTI(opts.PTI)
	req.SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink(0xff)
	req.SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink(0xff)

	pduSessionType := opts.PDUSessionType
	if pduSessionType == 0 {
		pduSessionType = nasMessage.PDUSessionTypeIPv4
	}

	req.PDUSessionType = nasType.NewPDUSessionType(nasMessage.PDUSessionEstablishmentRequestPDUSessionTypeType)
	req.SetPDUSessionTypeValue(pduSessionType)

	if opts.AlwaysOn {
		req.AlwaysonPDUSessionRequested = nasType.NewAlwaysonPDUSessionRequested(nasMessage.PDUSessionEstablishmentRequestAlwaysonPDUSessionRequestedType)
		req.SetAPSR(1)
	}

	req.ExtendedProtocolConfigurationOptions = nasType.NewExtendedProtocolConfigurationOptions(nasMessage.PDUSessionEstablishmentRequestExtendedProtocolConfigurationOptionsType)
	pco := nasConvert.NewProtocolConfigurationOptions()
	pco.AddIPAddressAllocationViaNASSignallingUL()
	pco.AddDNSServerIPv4AddressRequest()
	pco.AddDNSServerIPv6AddressRequest()
	pcoContents := pco.Marshal()
	req.ExtendedProtocolConfigurationOptions.SetLen(uint16(len(pcoContents)))
	req.SetExtendedProtocolConfigurationOptionsContents(pcoContents)

	m.PDUSessionEstablishmentRequest = req

	data := new(bytes.Buffer)
	if err := m.GsmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("GSM encode: %w", err)
	}

	return data.Bytes(), nil
}

func BuildULNASTransport(pduSessionID uint8, payloadContainer []byte, dnn string, sst int32, sd string) ([]byte, error) {
	m := gonas.NewMessage()
	m.GmmMessage = gonas.NewGmmMessage()
	m.GmmHeader.SetMessageType(gonas.MsgTypeULNASTransport)

	ul := nasMessage.NewULNASTransport(0)
	ul.SetSecurityHeaderType(gonas.SecurityHeaderTypePlainNas)
	ul.SetMessageType(gonas.MsgTypeULNASTransport)
	ul.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)

	ul.PduSessionID2Value = new(nasType.PduSessionID2Value)
	ul.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
	ul.SetPduSessionID2Value(pduSessionID)

	ul.RequestType = new(nasType.RequestType)
	ul.RequestType.SetIei(nasMessage.ULNASTransportRequestTypeType)
	ul.SetRequestTypeValue(nasMessage.ULNASTransportRequestTypeInitialRequest)

	if dnn != "" {
		ul.DNN = new(nasType.DNN)
		ul.DNN.SetIei(nasMessage.ULNASTransportDNNType)
		ul.DNN.SetLen(uint8(len(dnn)))
		ul.SetDNN(dnn)
	}

	ul.SNSSAI = nasType.NewSNSSAI(nasMessage.ULNASTransportSNSSAIType)
	if sd == "" {
		ul.SNSSAI.SetLen(1)
	} else {
		ul.SNSSAI.SetLen(4)
		var sdTemp [3]uint8
		sdBytes, err := hex.DecodeString(sd)
		if err != nil {
			return nil, fmt.Errorf("decode SD: %w", err)
		}
		copy(sdTemp[:], sdBytes)
		ul.SetSD(sdTemp)
	}
	ul.SetSST(uint8(sst))

	ul.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	ul.PayloadContainer.SetLen(uint16(len(payloadContainer)))
	ul.SetPayloadContainerContents(payloadContainer)

	m.ULNASTransport = ul

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("GMM encode: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionReleaseRequest builds a UE-requested PDU SESSION RELEASE
// REQUEST (TS 24.501 §8.3.8). The PTI is UE-allocated and echoed by the network
// in the resulting Release Command.
func BuildPDUSessionReleaseRequest(pduSessionID, pti uint8) ([]byte, error) {
	m := gonas.NewMessage()
	m.GsmMessage = gonas.NewGsmMessage()
	m.GsmHeader.SetMessageType(gonas.MsgTypePDUSessionReleaseRequest)

	req := nasMessage.NewPDUSessionReleaseRequest(0)
	req.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	req.SetMessageType(gonas.MsgTypePDUSessionReleaseRequest)
	req.SetPDUSessionID(pduSessionID)
	req.SetPTI(pti)

	m.PDUSessionReleaseRequest = req

	data := new(bytes.Buffer)
	if err := m.GsmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("GSM encode PDUSessionReleaseRequest: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionModificationRequest builds a UE-requested PDU SESSION
// MODIFICATION REQUEST (TS 24.501 §8.3.7) carrying only its mandatory IEs. The
// PTI is UE-allocated; the network echoes it in the resulting Modification
// Command or Reject (TS 24.501 §6.4.2.3/§6.4.2.4).
func BuildPDUSessionModificationRequest(pduSessionID, pti uint8) ([]byte, error) {
	m := gonas.NewMessage()
	m.GsmMessage = gonas.NewGsmMessage()
	m.GsmHeader.SetMessageType(gonas.MsgTypePDUSessionModificationRequest)

	req := nasMessage.NewPDUSessionModificationRequest(0)
	req.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	req.SetMessageType(gonas.MsgTypePDUSessionModificationRequest)
	req.SetPDUSessionID(pduSessionID)
	req.SetPTI(pti)

	m.PDUSessionModificationRequest = req

	data := new(bytes.Buffer)
	if err := m.GsmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("GSM encode PDUSessionModificationRequest: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionReleaseComplete builds a PDU SESSION RELEASE COMPLETE
// (TS 24.501 §8.3.10), acknowledging a Release Command. The PTI matches the one
// the network used in the command.
func BuildPDUSessionReleaseComplete(pduSessionID, pti uint8) ([]byte, error) {
	m := gonas.NewMessage()
	m.GsmMessage = gonas.NewGsmMessage()
	m.GsmHeader.SetMessageType(gonas.MsgTypePDUSessionReleaseComplete)

	cmp := nasMessage.NewPDUSessionReleaseComplete(0)
	cmp.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	cmp.SetMessageType(gonas.MsgTypePDUSessionReleaseComplete)
	cmp.SetPDUSessionID(pduSessionID)
	cmp.SetPTI(pti)

	m.PDUSessionReleaseComplete = cmp

	data := new(bytes.Buffer)
	if err := m.GsmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("GSM encode PDUSessionReleaseComplete: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionModificationComplete builds a PDU SESSION MODIFICATION
// COMPLETE (TS 24.501 §8.3.5), acknowledging a network-requested Modification
// Command. The PTI matches the one the network used in the command.
func BuildPDUSessionModificationComplete(pduSessionID, pti uint8) ([]byte, error) {
	m := gonas.NewMessage()
	m.GsmMessage = gonas.NewGsmMessage()
	m.GsmHeader.SetMessageType(gonas.MsgTypePDUSessionModificationComplete)

	cmp := nasMessage.NewPDUSessionModificationComplete(0)
	cmp.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	cmp.SetMessageType(gonas.MsgTypePDUSessionModificationComplete)
	cmp.SetPDUSessionID(pduSessionID)
	cmp.SetPTI(pti)

	m.PDUSessionModificationComplete = cmp

	data := new(bytes.Buffer)
	if err := m.GsmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("GSM encode PDUSessionModificationComplete: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionModificationCommandReject builds a PDU SESSION MODIFICATION
// COMMAND REJECT (TS 24.501 §8.3.6), rejecting a network-requested Modification
// Command. The PTI matches the command being rejected.
func BuildPDUSessionModificationCommandReject(pduSessionID, pti, cause uint8) ([]byte, error) {
	m := gonas.NewMessage()
	m.GsmMessage = gonas.NewGsmMessage()
	m.GsmHeader.SetMessageType(gonas.MsgTypePDUSessionModificationCommandReject)

	rej := nasMessage.NewPDUSessionModificationCommandReject(0)
	rej.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	rej.SetMessageType(gonas.MsgTypePDUSessionModificationCommandReject)
	rej.SetPDUSessionID(pduSessionID)
	rej.SetPTI(pti)
	rej.SetCauseValue(cause)

	m.PDUSessionModificationCommandReject = rej

	data := new(bytes.Buffer)
	if err := m.GsmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("GSM encode PDUSessionModificationCommandReject: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionStatus5GSM builds a 5GSM STATUS (TS 24.501 §8.3.13) reporting
// an erroneous condition for a PDU session, carrying the given PTI and cause.
func BuildPDUSessionStatus5GSM(pduSessionID, pti, cause uint8) ([]byte, error) {
	m := gonas.NewMessage()
	m.GsmMessage = gonas.NewGsmMessage()
	m.GsmHeader.SetMessageType(gonas.MsgTypeStatus5GSM)

	st := nasMessage.NewStatus5GSM(0)
	st.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	st.SetMessageType(gonas.MsgTypeStatus5GSM)
	st.SetPDUSessionID(pduSessionID)
	st.SetPTI(pti)
	st.SetCauseValue(cause)

	m.Status5GSM = st

	data := new(bytes.Buffer)
	if err := m.GsmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("GSM encode Status5GSM: %w", err)
	}

	return data.Bytes(), nil
}

// BuildULNASTransportExisting wraps a 5GSM message for an existing PDU session
// (release, modification) in a UL NAS TRANSPORT. Unlike BuildULNASTransport it
// omits the Request Type, DNN and S-NSSAI IEs, which are establishment-only;
// their absence makes the AMF forward the message to the SMF for the existing
// session rather than treating it as a new/duplicate session (TS 24.501 §8.2.10).
func BuildULNASTransportExisting(pduSessionID uint8, requestType *uint8, payloadContainer []byte) ([]byte, error) {
	m := gonas.NewMessage()
	m.GmmMessage = gonas.NewGmmMessage()
	m.GmmHeader.SetMessageType(gonas.MsgTypeULNASTransport)

	ul := nasMessage.NewULNASTransport(0)
	ul.SetSecurityHeaderType(gonas.SecurityHeaderTypePlainNas)
	ul.SetMessageType(gonas.MsgTypeULNASTransport)
	ul.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)

	ul.PduSessionID2Value = new(nasType.PduSessionID2Value)
	ul.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
	ul.SetPduSessionID2Value(pduSessionID)

	if requestType != nil {
		ul.RequestType = new(nasType.RequestType)
		ul.RequestType.SetIei(nasMessage.ULNASTransportRequestTypeType)
		ul.SetRequestTypeValue(*requestType)
	}

	ul.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	ul.PayloadContainer.SetLen(uint16(len(payloadContainer)))
	ul.SetPayloadContainerContents(payloadContainer)

	m.ULNASTransport = ul

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("GMM encode: %w", err)
	}

	return data.Bytes(), nil
}

func DecodePDUSessionEstablishmentAccept(nasResp *NASResponse, gsmMsg *gonas.GsmMessage) {
	if gsmMsg == nil || gsmMsg.PDUSessionEstablishmentAccept == nil {
		return
	}

	msg := gsmMsg.PDUSessionEstablishmentAccept

	nasResp.PDUSessionID = msg.GetPDUSessionID()
	nasResp.PDUSessionType = msg.SelectedSSCModeAndSelectedPDUSessionType.Octet & 0x07

	pduAddr := msg.GetPDUAddressInformation()
	switch nasResp.PDUSessionType {
	case nasMessage.PDUSessionTypeIPv4:
		nasResp.PDUAddress = fmt.Sprintf("%d.%d.%d.%d", pduAddr[0], pduAddr[1], pduAddr[2], pduAddr[3])
	case nasMessage.PDUSessionTypeIPv6:
		nasResp.PDUAddress = hex.EncodeToString(pduAddr[:])
	case nasMessage.PDUSessionTypeIPv4IPv6:
		nasResp.PDUAddress = fmt.Sprintf("%d.%d.%d.%d", pduAddr[8], pduAddr[9], pduAddr[10], pduAddr[11])
	}

	ulAMBR := msg.GetSessionAMBRForUplink()
	nasResp.SessionAMBRUplink = uint16(ulAMBR[0])<<8 | uint16(ulAMBR[1])

	dlAMBR := msg.GetSessionAMBRForDownlink()
	nasResp.SessionAMBRDownlink = uint16(dlAMBR[0])<<8 | uint16(dlAMBR[1])

	if ruleLen := msg.AuthorizedQosRules.GetLen(); ruleLen > 0 {
		nasResp.AuthorizedQoSRules = hex.EncodeToString(msg.AuthorizedQosRules.Buffer[:ruleLen])
	}

	if msg.AlwaysonPDUSessionIndication != nil {
		apsi := msg.GetAPSI()
		nasResp.AlwaysOnIndication = &apsi
	}

	// The Accept carries a 5GSM cause when the network downgrades the requested
	// PDU session type (TS 24.501 §6.4.1.3): #50 "IPv4 only allowed" or #51
	// "IPv6 only allowed".
	if msg.Cause5GSM != nil {
		cause := msg.GetCauseValue()
		nasResp.Cause5GSM = &cause
	}
}

func DecodePDUSessionEstablishmentReject(nasResp *NASResponse, gsmMsg *gonas.GsmMessage) {
	if gsmMsg == nil || gsmMsg.PDUSessionEstablishmentReject == nil {
		return
	}

	cause := gsmMsg.PDUSessionEstablishmentReject.GetCauseValue()
	nasResp.Cause5GSM = &cause
}
