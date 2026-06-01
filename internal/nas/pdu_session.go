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
	req.SetPTI(0x01)
	req.SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForDownLink(0xff)
	req.SetMaximumDataRatePerUEForUserPlaneIntegrityProtectionForUpLink(0xff)

	pduSessionType := opts.PDUSessionType
	if pduSessionType == 0 {
		pduSessionType = nasMessage.PDUSessionTypeIPv4
	}

	req.PDUSessionType = nasType.NewPDUSessionType(nasMessage.PDUSessionEstablishmentRequestPDUSessionTypeType)
	req.SetPDUSessionTypeValue(pduSessionType)

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

// BuildULNASTransportExisting wraps a 5GSM message for an existing PDU session
// (release, modification) in a UL NAS TRANSPORT. Unlike BuildULNASTransport it
// omits the Request Type, DNN and S-NSSAI IEs, which are establishment-only;
// their absence makes the AMF forward the message to the SMF for the existing
// session rather than treating it as a new/duplicate session (TS 24.501 §8.2.10).
func BuildULNASTransportExisting(pduSessionID uint8, payloadContainer []byte) ([]byte, error) {
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
}

func DecodePDUSessionEstablishmentReject(nasResp *NASResponse, gsmMsg *gonas.GsmMessage) {
	if gsmMsg == nil || gsmMsg.PDUSessionEstablishmentReject == nil {
		return
	}

	cause := gsmMsg.PDUSessionEstablishmentReject.GetCauseValue()
	nasResp.Cause5GSM = &cause
}
