// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas5gs

import (
	"encoding/hex"
	"fmt"

	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

func Decode(data []byte) (*NASResponse, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("nas: empty NAS PDU")
	}

	resp := &NASResponse{
		RawHex: hex.EncodeToString(data),
	}

	m := new(gonas.Message)
	m.SecurityHeaderType = gonas.GetSecurityHeaderType(data) & 0x0f

	payload := make([]byte, len(data))
	copy(payload, data)

	resp.SecurityHeaderType = SecurityHeaderTypeString(m.SecurityHeaderType)

	if m.SecurityHeaderType != gonas.SecurityHeaderTypePlainNas {
		resp.MessageType = "secured_nas"
		return resp, nil
	}

	if err := m.PlainNasDecode(&payload); err != nil {
		return nil, fmt.Errorf("nas: plain NAS decode: %w", err)
	}

	if m.GmmMessage == nil {
		messageType, err := unknownMessageType(m)
		if err != nil {
			return nil, err
		}

		resp.MessageType = messageType

		return resp, nil
	}

	if err := decodeGmm(m, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func decodeGmm(m *gonas.Message, resp *NASResponse) error {
	msgType := m.GmmMessage.GetMessageType()
	resp.MessageType = gmmMessageTypeName(msgType)

	switch msgType {
	case gonas.MsgTypeAuthenticationRequest:
		decodeAuthenticationRequest(m, resp)
	case gonas.MsgTypeIdentityRequest:
		decodeIdentityRequest(m, resp)
	case gonas.MsgTypeSecurityModeCommand:
		decodeSecurityModeCommand(m, resp)
	case gonas.MsgTypeRegistrationAccept:
		decodeRegistrationAccept(m, resp)
	case gonas.MsgTypeRegistrationReject:
		decodeRegistrationReject(m, resp)
	case gonas.MsgTypeServiceAccept:
		decodeServiceAccept(m, resp)
	case gonas.MsgTypeServiceReject:
		decodeServiceReject(m, resp)
	case gonas.MsgTypeStatus5GMM:
		decodeStatus5GMM(m, resp)
	case gonas.MsgTypeDLNASTransport:
		return decodeDLNASTransport(m, resp)
	}

	return nil
}

func unknownMessageType(m *gonas.Message) (string, error) {
	if m.GsmMessage == nil {
		return "", fmt.Errorf("nas: decoded message carries neither a 5GMM nor a 5GSM message")
	}

	return fmt.Sprintf("gsm_message_%#x", m.GsmMessage.GetMessageType()), nil
}

func decodeAuthenticationRequest(m *gonas.Message, resp *NASResponse) {
	if m.AuthenticationRequest == nil {
		return
	}

	rand := m.GetRANDValue()
	resp.RAND = hex.EncodeToString(rand[:])

	autn := m.GetAUTN()
	resp.AUTN = hex.EncodeToString(autn[:])

	if m.AuthenticationRequest.ABBA.Len > 0 {
		resp.ABBAContents = hex.EncodeToString(m.AuthenticationRequest.ABBA.Buffer[:m.AuthenticationRequest.ABBA.Len])
	}

	ksi := int(m.AuthenticationRequest.GetNasKeySetIdentifiler())
	resp.NgKSI = &ksi

	if m.AuthenticationRequest.EAPMessage != nil {
		eapLen := m.AuthenticationRequest.EAPMessage.GetLen()
		if eapLen > 0 {
			resp.EAPMessage = hex.EncodeToString(m.AuthenticationRequest.EAPMessage.Buffer[:eapLen])
		}
	}
}

func decodeIdentityRequest(m *gonas.Message, resp *NASResponse) {
	if m.IdentityRequest == nil {
		return
	}
	idType := int(m.SpareHalfOctetAndIdentityType.GetTypeOfIdentity())
	resp.IdentityType = &idType
}

func decodeRegistrationReject(m *gonas.Message, resp *NASResponse) {
	if m.RegistrationReject == nil {
		return
	}
	cause := int(m.RegistrationReject.GetCauseValue())
	resp.FiveGMMCause = &cause
}

func decodeServiceReject(m *gonas.Message, resp *NASResponse) {
	if m.ServiceReject == nil {
		return
	}
	cause := int(m.ServiceReject.GetCauseValue())
	resp.FiveGMMCause = &cause
}

func decodeSecurityModeCommand(m *gonas.Message, resp *NASResponse) {
	if m.SecurityModeCommand == nil {
		return
	}

	cipherAlg := int(m.SelectedNASSecurityAlgorithms.GetTypeOfCipheringAlgorithm())
	resp.SelectedCipheringAlgorithm = &cipherAlg

	integAlg := int(m.SelectedNASSecurityAlgorithms.GetTypeOfIntegrityProtectionAlgorithm())
	resp.SelectedIntegrityAlgorithm = &integAlg

	ksi := int(m.SecurityModeCommand.GetNasKeySetIdentifiler())
	resp.NgKSI = &ksi

	if rc := m.ReplayedUESecurityCapabilities; rc.GetLen() > 0 {
		resp.ReplayedUESecurityCapabilities = hex.EncodeToString(rc.Buffer)
	}

	if m.IMEISVRequest != nil {
		resp.IMEISVRequested = true
	}
}

func decodeRegistrationAccept(m *gonas.Message, resp *NASResponse) {
	if m.RegistrationAccept == nil {
		return
	}

	if m.RegistrationAccept.GUTI5G != nil {
		gutiLen := m.RegistrationAccept.GUTI5G.GetLen()
		if gutiLen > 0 && gutiLen <= 11 {
			resp.GUTI = guti5GStructured(m.RegistrationAccept.GUTI5G)
		}
	}

	if m.RegistrationAccept.TAIList != nil {
		taiLen := int(m.RegistrationAccept.TAIList.GetLen())
		if taiLen > 0 && taiLen <= len(m.RegistrationAccept.TAIList.Buffer) {
			resp.TAIList = hex.EncodeToString(m.RegistrationAccept.TAIList.Buffer[:taiLen])
		}
	}
}

func decodeServiceAccept(m *gonas.Message, resp *NASResponse) {
	if m.ServiceAccept == nil || m.ServiceAccept.PDUSessionStatus == nil {
		return
	}

	statusLen := int(m.ServiceAccept.PDUSessionStatus.GetLen())
	if statusLen > 0 && statusLen <= len(m.ServiceAccept.PDUSessionStatus.Buffer) {
		resp.PDUSessionStatus = hex.EncodeToString(m.ServiceAccept.PDUSessionStatus.Buffer[:statusLen])
	}
}

// SecurityHeaderTypeString renders a 5GS security header type for JSON (TS 24.501 §9.3).
func SecurityHeaderTypeString(t SecurityHeaderType) string {
	switch t {
	case gonas.SecurityHeaderTypePlainNas:
		return "plain"
	case gonas.SecurityHeaderTypeIntegrityProtected:
		return "integrity_protected"
	case gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered:
		return "integrity_protected_and_ciphered"
	case gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext:
		return "integrity_protected_with_new_5g_nas_security_context"
	case gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext:
		return "integrity_protected_and_ciphered_with_new_5g_nas_security_context"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

func decodeDLNASTransport(m *gonas.Message, resp *NASResponse) error {
	if m.DLNASTransport == nil {
		return nil
	}

	if m.DLNASTransport.Cause5GMM != nil {
		cause := int(m.DLNASTransport.GetCauseValue())
		resp.FiveGMMCause = &cause
	}

	payload := m.DLNASTransport.GetPayloadContainerContents()
	if len(payload) == 0 {
		return nil
	}

	if m.DLNASTransport.GetPayloadContainerType() != nasMessage.PayloadContainerTypeN1SMInfo {
		return nil
	}

	inner := new(gonas.Message)
	if err := inner.GsmMessageDecode(&payload); err != nil {
		return fmt.Errorf("nas: decode DL NAS transport payload: %w", err)
	}

	if inner.GsmMessage == nil {
		return nil
	}

	innerType := inner.GsmHeader.GetMessageType()
	resp.InnerNASMessageType = gsmMessageTypeName(innerType)

	switch innerType {
	case gonas.MsgTypePDUSessionEstablishmentAccept:
		decodePDUSessionEstablishmentAccept(resp, inner.GsmMessage)
	case gonas.MsgTypePDUSessionEstablishmentReject:
		decodePDUSessionEstablishmentReject(resp, inner.GsmMessage)
	case gonas.MsgTypePDUSessionReleaseCommand:
		decodePDUSessionReleaseCommand(resp, inner.GsmMessage, payload)
	case gonas.MsgTypePDUSessionModificationReject:
		if inner.PDUSessionModificationReject != nil {
			cause := int(inner.PDUSessionModificationReject.GetCauseValue())
			resp.FiveGSMCause = &cause
		}
	case gonas.MsgTypeStatus5GSM:
		if inner.Status5GSM != nil {
			cause := int(inner.Status5GSM.GetCauseValue())
			resp.FiveGSMCause = &cause
		}
	}

	return nil
}

func gsmMessageTypeName(t uint8) string {
	switch t {
	case gonas.MsgTypePDUSessionEstablishmentRequest:
		return "pdu_session_establishment_request"
	case gonas.MsgTypePDUSessionEstablishmentAccept:
		return "pdu_session_establishment_accept"
	case gonas.MsgTypePDUSessionEstablishmentReject:
		return "pdu_session_establishment_reject"
	case gonas.MsgTypePDUSessionModificationRequest:
		return "pdu_session_modification_request"
	case gonas.MsgTypePDUSessionModificationReject:
		return "pdu_session_modification_reject"
	case gonas.MsgTypePDUSessionModificationCommand:
		return "pdu_session_modification_command"
	case gonas.MsgTypePDUSessionReleaseRequest:
		return "pdu_session_release_request"
	case gonas.MsgTypePDUSessionReleaseReject:
		return "pdu_session_release_reject"
	case gonas.MsgTypePDUSessionReleaseCommand:
		return "pdu_session_release_command"
	case gonas.MsgTypePDUSessionReleaseComplete:
		return "pdu_session_release_complete"
	case gonas.MsgTypeStatus5GSM:
		return "5gsm_status"
	default:
		return fmt.Sprintf("gsm_message_%#x", t)
	}
}

// guti5GStructured decodes a 5G-GUTI into its fields (TS 24.501 §9.11.3.4).
func guti5GStructured(g *nasType.GUTI5G) *GUTI5GJSON {
	mcc := fmt.Sprintf("%d%d%d", g.GetMCCDigit1(), g.GetMCCDigit2(), g.GetMCCDigit3())

	mnc := fmt.Sprintf("%d%d", g.GetMNCDigit1(), g.GetMNCDigit2())
	if d3 := g.GetMNCDigit3(); d3 != 0x0f {
		mnc += fmt.Sprintf("%d", d3)
	}

	tmsi := g.GetTMSI5G()

	return &GUTI5GJSON{
		MCC:         mcc,
		MNC:         mnc,
		AMFRegionID: int(g.GetAMFRegionID()),
		AMFSetID:    int(g.GetAMFSetID()),
		AMFPointer:  int(g.GetAMFPointer()),
		FiveGTMSI:   hex.EncodeToString(tmsi[:]),
	}
}

// GUTI5GFromStructured re-encodes a decoded 5G-GUTI for reuse in a later uplink
// message (TS 24.501 §9.11.3.4); it is the inverse of guti5GStructured.
func GUTI5GFromStructured(s *GUTI5GJSON) *nasType.GUTI5G {
	if s == nil {
		return nil
	}

	g := nasType.NewGUTI5G(0)
	g.SetLen(11)
	g.SetSpare(0)
	g.SetSpare2(0)
	g.SetTypeOfIdentity(nasMessage.MobileIdentity5GSType5gGuti)

	if len(s.MCC) == 3 {
		g.SetMCCDigit1(s.MCC[0] - '0')
		g.SetMCCDigit2(s.MCC[1] - '0')
		g.SetMCCDigit3(s.MCC[2] - '0')
	}

	switch len(s.MNC) {
	case 2:
		g.SetMNCDigit1(s.MNC[0] - '0')
		g.SetMNCDigit2(s.MNC[1] - '0')
		g.SetMNCDigit3(0x0f)
	case 3:
		g.SetMNCDigit1(s.MNC[0] - '0')
		g.SetMNCDigit2(s.MNC[1] - '0')
		g.SetMNCDigit3(s.MNC[2] - '0')
	}

	g.SetAMFRegionID(uint8(s.AMFRegionID))
	g.SetAMFSetID(uint16(s.AMFSetID))
	g.SetAMFPointer(uint8(s.AMFPointer))

	var tmsi [4]byte
	if b, err := hex.DecodeString(s.FiveGTMSI); err == nil {
		copy(tmsi[:], b)
	}

	g.SetTMSI5G(tmsi)

	return g
}

func decodeStatus5GMM(m *gonas.Message, resp *NASResponse) {
	if m.Status5GMM == nil {
		return
	}

	cause := int(m.Status5GMM.GetCauseValue())
	resp.FiveGMMCause = &cause
}

func gmmMessageTypeName(t uint8) string {
	switch t {
	case gonas.MsgTypeRegistrationRequest:
		return "registration_request"
	case gonas.MsgTypeRegistrationAccept:
		return "registration_accept"
	case gonas.MsgTypeRegistrationComplete:
		return "registration_complete"
	case gonas.MsgTypeRegistrationReject:
		return "registration_reject"
	case gonas.MsgTypeAuthenticationRequest:
		return "authentication_request"
	case gonas.MsgTypeAuthenticationResponse:
		return "authentication_response"
	case gonas.MsgTypeAuthenticationReject:
		return "authentication_reject"
	case gonas.MsgTypeAuthenticationResult:
		return "authentication_result"
	case gonas.MsgTypeIdentityRequest:
		return "identity_request"
	case gonas.MsgTypeIdentityResponse:
		return "identity_response"
	case gonas.MsgTypeSecurityModeCommand:
		return "security_mode_command"
	case gonas.MsgTypeSecurityModeComplete:
		return "security_mode_complete"
	case gonas.MsgTypeSecurityModeReject:
		return "security_mode_reject"
	case gonas.MsgTypeServiceRequest:
		return "service_request"
	case gonas.MsgTypeServiceAccept:
		return "service_accept"
	case gonas.MsgTypeServiceReject:
		return "service_reject"
	case gonas.MsgTypeDeregistrationRequestUEOriginatingDeregistration:
		return "deregistration_request"
	case gonas.MsgTypeDeregistrationAcceptUEOriginatingDeregistration:
		return "deregistration_accept"
	case gonas.MsgTypeDeregistrationRequestUETerminatedDeregistration:
		return "deregistration_request_ue_terminated"
	case gonas.MsgTypeDeregistrationAcceptUETerminatedDeregistration:
		return "deregistration_accept_ue_terminated"
	case gonas.MsgTypeDLNASTransport:
		return "dl_nas_transport"
	case gonas.MsgTypeULNASTransport:
		return "ul_nas_transport"
	case gonas.MsgTypeConfigurationUpdateCommand:
		return "configuration_update_command"
	case gonas.MsgTypeConfigurationUpdateComplete:
		return "configuration_update_complete"
	case gonas.MsgTypeStatus5GMM:
		return "status_5gmm"
	default:
		return fmt.Sprintf("gmm_message_%#x", t)
	}
}
