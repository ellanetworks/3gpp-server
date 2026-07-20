// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas5gs

import (
	"bytes"
	"encoding/hex"
	"fmt"

	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

type PDUSessionEstablishmentRequestParams struct {
	PDUSessionID   uint8
	PDUSessionType uint8
	PTI            uint8
	AlwaysOn       bool
	DNN            string
	SST            int32
	SD             string
}

// BuildPDUSessionEstablishmentRequest builds a PDU SESSION ESTABLISHMENT REQUEST (TS 24.501 §8.3.1).
func BuildPDUSessionEstablishmentRequest(opts PDUSessionEstablishmentRequestParams) ([]byte, error) {
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
		return nil, fmt.Errorf("nas: GSM encode: %w", err)
	}

	return data.Bytes(), nil
}

type ULNASTransportParams struct {
	PduSessionID     uint8
	PayloadContainer []byte
	DNN              string
	SST              int32
	SD               string
}

// BuildULNASTransport wraps a 5GSM message establishing a new PDU session in a UL NAS TRANSPORT (TS 24.501 §8.2.10).
func BuildULNASTransport(opts ULNASTransportParams) ([]byte, error) {
	m := gonas.NewMessage()
	m.GmmMessage = gonas.NewGmmMessage()
	m.GmmHeader.SetMessageType(gonas.MsgTypeULNASTransport)

	ul := nasMessage.NewULNASTransport(0)
	ul.SetSecurityHeaderType(gonas.SecurityHeaderTypePlainNas)
	ul.SetMessageType(gonas.MsgTypeULNASTransport)
	ul.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)

	ul.PduSessionID2Value = new(nasType.PduSessionID2Value)
	ul.PduSessionID2Value.SetIei(nasMessage.ULNASTransportPduSessionID2ValueType)
	ul.SetPduSessionID2Value(opts.PduSessionID)

	ul.RequestType = new(nasType.RequestType)
	ul.RequestType.SetIei(nasMessage.ULNASTransportRequestTypeType)
	ul.SetRequestTypeValue(nasMessage.ULNASTransportRequestTypeInitialRequest)

	if opts.DNN != "" {
		ul.DNN = new(nasType.DNN)
		ul.DNN.SetIei(nasMessage.ULNASTransportDNNType)
		ul.DNN.SetLen(uint8(len(opts.DNN)))
		ul.SetDNN(opts.DNN)
	}

	ul.SNSSAI = nasType.NewSNSSAI(nasMessage.ULNASTransportSNSSAIType)
	if opts.SD == "" {
		ul.SNSSAI.SetLen(1)
	} else {
		ul.SNSSAI.SetLen(4)
		var sdTemp [3]uint8
		sdBytes, err := hex.DecodeString(opts.SD)
		if err != nil {
			return nil, fmt.Errorf("nas: decode SD: %w", err)
		}
		copy(sdTemp[:], sdBytes)
		ul.SetSD(sdTemp)
	}
	ul.SetSST(uint8(opts.SST))

	ul.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	ul.PayloadContainer.SetLen(uint16(len(opts.PayloadContainer)))
	ul.SetPayloadContainerContents(opts.PayloadContainer)

	m.ULNASTransport = ul

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionReleaseRequest builds a UE-requested PDU SESSION RELEASE REQUEST (TS 24.501 §8.3.8).
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
		return nil, fmt.Errorf("nas: GSM encode PDUSessionReleaseRequest: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionModificationRequest builds a UE-requested PDU SESSION MODIFICATION REQUEST (TS 24.501 §8.3.7).
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
		return nil, fmt.Errorf("nas: GSM encode PDUSessionModificationRequest: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionReleaseComplete builds a PDU SESSION RELEASE COMPLETE (TS 24.501 §8.3.10).
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
		return nil, fmt.Errorf("nas: GSM encode PDUSessionReleaseComplete: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionModificationComplete builds a PDU SESSION MODIFICATION COMPLETE (TS 24.501 §8.3.5).
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
		return nil, fmt.Errorf("nas: GSM encode PDUSessionModificationComplete: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionModificationCommandReject builds a PDU SESSION MODIFICATION COMMAND REJECT (TS 24.501 §8.3.6).
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
		return nil, fmt.Errorf("nas: GSM encode PDUSessionModificationCommandReject: %w", err)
	}

	return data.Bytes(), nil
}

// BuildPDUSessionStatus5GSM builds a 5GSM STATUS (TS 24.501 §8.3.13).
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
		return nil, fmt.Errorf("nas: GSM encode Status5GSM: %w", err)
	}

	return data.Bytes(), nil
}

// BuildULNASTransportExisting wraps a 5GSM message in a UL NAS TRANSPORT (TS 24.501 §8.2.10); omitting DNN and S-NSSAI routes it to the existing session's SMF.
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
		return nil, fmt.Errorf("nas: GMM encode: %w", err)
	}

	return data.Bytes(), nil
}

func DecodePDUSessionEstablishmentAccept(nasResp *NASResponse, gsmMsg *gonas.GsmMessage) {
	if gsmMsg == nil || gsmMsg.PDUSessionEstablishmentAccept == nil {
		return
	}

	msg := gsmMsg.PDUSessionEstablishmentAccept

	pduSessionID := int(msg.GetPDUSessionID())
	nasResp.PDUSessionID = &pduSessionID

	pti := int(msg.GetPTI())
	nasResp.PTI = &pti

	pduSessionType := msg.GetPDUSessionType()
	pduSessionTypeValue := int(pduSessionType)
	nasResp.PDUSessionType = &pduSessionTypeValue

	sscMode := int(msg.GetSSCMode())
	nasResp.SSCMode = &sscMode

	if msg.PDUAddress != nil {
		pduAddr := msg.GetPDUAddressInformation()
		switch pduSessionType {
		case nasMessage.PDUSessionTypeIPv4:
			nasResp.PDUAddress = fmt.Sprintf("%d.%d.%d.%d", pduAddr[0], pduAddr[1], pduAddr[2], pduAddr[3])
		case nasMessage.PDUSessionTypeIPv6:
			nasResp.PDUAddress = hex.EncodeToString(pduAddr[:])
		case nasMessage.PDUSessionTypeIPv4IPv6:
			nasResp.PDUAddress = fmt.Sprintf("%d.%d.%d.%d", pduAddr[8], pduAddr[9], pduAddr[10], pduAddr[11])
		}
	}

	ulAMBR := msg.GetSessionAMBRForUplink()
	ulAMBRValue := int(uint16(ulAMBR[0])<<8 | uint16(ulAMBR[1]))
	nasResp.SessionAMBRUplink = &ulAMBRValue

	dlAMBR := msg.GetSessionAMBRForDownlink()
	dlAMBRValue := int(uint16(dlAMBR[0])<<8 | uint16(dlAMBR[1]))
	nasResp.SessionAMBRDownlink = &dlAMBRValue

	if ruleLen := msg.AuthorizedQosRules.GetLen(); ruleLen > 0 {
		nasResp.AuthorizedQoSRules = hex.EncodeToString(msg.AuthorizedQosRules.Buffer[:ruleLen])
	}

	if msg.AlwaysonPDUSessionIndication != nil {
		apsi := int(msg.GetAPSI())
		nasResp.AlwaysOnIndication = &apsi
	}

	if msg.Cause5GSM != nil {
		cause := int(msg.GetCauseValue())
		nasResp.FiveGSMCause = &cause
	}
}

func DecodePDUSessionReleaseCommand(nasResp *NASResponse, gsmMsg *gonas.GsmMessage, raw []byte) {
	if gsmMsg == nil || gsmMsg.PDUSessionReleaseCommand == nil {
		return
	}

	msg := gsmMsg.PDUSessionReleaseCommand

	pti := int(msg.GetPTI())
	nasResp.PTI = &pti

	cause := int(msg.GetCauseValue())
	nasResp.FiveGSMCause = &cause

	accessType := releaseCommandHasAccessType(raw)
	nasResp.AccessTypePresent = &accessType
}

// TS 24.501 Table 8.3.14.1.1; free5gc has no constant for it.
const serviceLevelAAContainerIEI = 0x72

// TS 24.501 Table 8.3.14.1.1: the Access type IE is a type 1 IE, which free5gc's
// PDU SESSION RELEASE COMMAND decoder skips without recording.
func releaseCommandHasAccessType(raw []byte) bool {
	const (
		mandatoryOctets = 5
		accessTypeIEI   = 0xd
	)

	if len(raw) < mandatoryOctets {
		return false
	}

	for opt := raw[mandatoryOctets:]; len(opt) > 0; {
		iei := opt[0]

		if iei >= 0x80 {
			if iei>>4 == accessTypeIEI {
				return true
			}
			opt = opt[1:]

			continue
		}

		lenOctets := 1
		switch iei {
		case nasMessage.PDUSessionReleaseCommandEAPMessageType,
			nasMessage.PDUSessionReleaseCommandExtendedProtocolConfigurationOptionsType,
			serviceLevelAAContainerIEI:
			lenOctets = 2
		}

		if len(opt) < 1+lenOctets {
			return false
		}

		contents := int(opt[1])
		if lenOctets == 2 {
			contents = int(opt[1])<<8 | int(opt[2])
		}

		skip := 1 + lenOctets + contents
		if len(opt) < skip {
			return false
		}

		opt = opt[skip:]
	}

	return false
}

func DecodePDUSessionEstablishmentReject(nasResp *NASResponse, gsmMsg *gonas.GsmMessage) {
	if gsmMsg == nil || gsmMsg.PDUSessionEstablishmentReject == nil {
		return
	}

	cause := int(gsmMsg.PDUSessionEstablishmentReject.GetCauseValue())
	nasResp.FiveGSMCause = &cause
}
