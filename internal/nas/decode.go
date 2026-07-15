// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"encoding/hex"
	"fmt"

	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

func Decode(data []byte) (*NASResponse, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty NAS PDU")
	}

	resp := &NASResponse{
		RawHex: hex.EncodeToString(data),
	}

	m := new(gonas.Message)
	m.SecurityHeaderType = gonas.GetSecurityHeaderType(data) & 0x0f

	payload := make([]byte, len(data))
	copy(payload, data)

	resp.SecurityHeaderType = securityHeaderTypeToString(m.SecurityHeaderType)

	if m.SecurityHeaderType != gonas.SecurityHeaderTypePlainNas {
		resp.MessageType = "secured_nas"
		return resp, nil
	}

	if err := m.PlainNasDecode(&payload); err != nil {
		return nil, fmt.Errorf("NAS decode error: %v", err)
	}

	if m.GmmMessage == nil {
		resp.MessageType = unknownMessageType(m)
		return resp, nil
	}

	if err := decodeGmm(m, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// decodeGmm names a decoded plain 5GMM message and surfaces its IEs. Both the
// plain path and the unwrapped-secured path dispatch through this one table: a
// message carries the same IEs whichever way it arrived, so a message the core
// sends unprotected still yields the fields that show what it sent.
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
	case gonas.MsgTypeServiceReject:
		decodeServiceReject(m, resp)
	case gonas.MsgTypeStatus5GMM:
		decodeStatus5GMM(m, resp)
	case gonas.MsgTypeDLNASTransport:
		return decodeDLNASTransport(m, resp)
	}

	return nil
}

// unknownMessageType labels a decoded downlink the dispatch tables do not cover,
// keeping the numeric 5GS message type (TS 24.501 §9.7) so a malformed downlink
// stays identifiable. A nil GmmMessage means PlainNasDecode parsed a top-level
// 5GSM message.
func unknownMessageType(m *gonas.Message) string {
	if m.GsmMessage != nil {
		return fmt.Sprintf("gsm_message_%#x", m.GsmMessage.GetMessageType())
	}

	return "unknown"
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

	ksi := m.AuthenticationRequest.GetNasKeySetIdentifiler()
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
	idType := m.SpareHalfOctetAndIdentityType.GetTypeOfIdentity()
	resp.IdentityType = &idType
}

func decodeRegistrationReject(m *gonas.Message, resp *NASResponse) {
	if m.RegistrationReject == nil {
		return
	}
	cause := m.RegistrationReject.GetCauseValue()
	resp.CauseGMM = &cause
}

func decodeServiceReject(m *gonas.Message, resp *NASResponse) {
	if m.ServiceReject == nil {
		return
	}
	cause := m.ServiceReject.GetCauseValue()
	resp.CauseGMM = &cause
}

func decodeSecurityModeCommand(m *gonas.Message, resp *NASResponse) {
	if m.SecurityModeCommand == nil {
		return
	}

	cipherAlg := m.SelectedNASSecurityAlgorithms.GetTypeOfCipheringAlgorithm()
	resp.SelectedCipheringAlg = &cipherAlg

	integAlg := m.SelectedNASSecurityAlgorithms.GetTypeOfIntegrityProtectionAlgorithm()
	resp.SelectedIntegrityAlg = &integAlg

	ksi := m.SecurityModeCommand.GetNasKeySetIdentifiler()
	resp.NgKSI = &ksi
}

func decodeRegistrationAccept(m *gonas.Message, resp *NASResponse) {
	if m.RegistrationAccept == nil {
		return
	}

	if m.RegistrationAccept.GUTI5G != nil {
		gutiLen := m.RegistrationAccept.GUTI5G.GetLen()
		if gutiLen > 0 && gutiLen <= 11 {
			resp.GUTI = hex.EncodeToString(m.RegistrationAccept.GUTI5G.Octet[:gutiLen])
		}
	}
}

func securityHeaderTypeToString(t uint8) string {
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
		cause := m.DLNASTransport.GetCauseValue()
		resp.CauseGMM = &cause
	}

	payload := m.DLNASTransport.GetPayloadContainerContents()
	if len(payload) == 0 {
		return nil
	}

	// The payload container holds a 5GSM message only when its type is N1 SM
	// information (TS 24.501 §9.11.3.40); other container types are not NAS.
	if m.DLNASTransport.GetPayloadContainerType() != nasMessage.PayloadContainerTypeN1SMInfo {
		return nil
	}

	inner := new(gonas.Message)
	if err := inner.GsmMessageDecode(&payload); err != nil {
		return fmt.Errorf("decode DL NAS transport payload: %w", err)
	}

	if inner.GsmMessage == nil {
		return nil
	}

	innerType := inner.GsmHeader.GetMessageType()
	resp.InnerNASMessageType = gsmMessageTypeName(innerType)

	switch innerType {
	case gonas.MsgTypePDUSessionEstablishmentAccept:
		DecodePDUSessionEstablishmentAccept(resp, inner.GsmMessage)
	case gonas.MsgTypePDUSessionEstablishmentReject:
		DecodePDUSessionEstablishmentReject(resp, inner.GsmMessage)
	case gonas.MsgTypePDUSessionReleaseCommand:
		if inner.PDUSessionReleaseCommand != nil {
			cause := inner.PDUSessionReleaseCommand.GetCauseValue()
			resp.Cause5GSM = &cause
		}
	case gonas.MsgTypePDUSessionModificationReject:
		if inner.PDUSessionModificationReject != nil {
			cause := inner.PDUSessionModificationReject.GetCauseValue()
			resp.Cause5GSM = &cause
		}
	case gonas.MsgTypeStatus5GSM:
		if inner.Status5GSM != nil {
			cause := inner.Status5GSM.GetCauseValue()
			resp.Cause5GSM = &cause
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
		return fmt.Sprintf("unknown_gsm(%d)", t)
	}
}

func ParseGUTI(contents []byte) *nasType.GUTI5G {
	if len(contents) < 11 {
		return nil
	}

	guti := &nasType.GUTI5G{}
	guti.Len = uint16(len(contents))
	copy(guti.Octet[:], contents)

	return guti
}

func decodeStatus5GMM(m *gonas.Message, resp *NASResponse) {
	if m.Status5GMM == nil {
		return
	}

	cause := m.Status5GMM.GetCauseValue()
	resp.CauseGMM = &cause
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
		return fmt.Sprintf("unknown(%d)", t)
	}
}
