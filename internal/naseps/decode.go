// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import (
	"encoding/hex"
	"fmt"

	"github.com/ellanetworks/core/nas/eps"
)

// SecurityHeaderTypeString renders an EPS security header type for JSON (TS 24.301 §9.3.1).
func SecurityHeaderTypeString(t SecurityHeaderType) string {
	switch t {
	case SHTPlain:
		return "plain"
	case SHTIntegrityProtected:
		return "integrity_protected"
	case SHTIntegrityProtectedCiphered:
		return "integrity_protected_and_ciphered"
	case SHTIntegrityProtectedNewContext:
		return "integrity_protected_with_new_eps_security_context"
	case SHTIntegrityProtectedCipheredNew:
		return "integrity_protected_and_ciphered_with_new_eps_security_context"
	case eps.SHTServiceRequest:
		return "service_request"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(t))
	}
}

func SecurityHeader(b []byte) (SecurityHeaderType, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("naseps: empty NAS message")
	}

	if b[0]&0x0F != eps.PDEMM {
		return 0, fmt.Errorf("naseps: not an EMM message (PD %#x)", b[0]&0x0F)
	}

	return SecurityHeaderType(b[0] >> 4), nil
}

// PeekProtectedPayload skips MAC verification: a Security Mode Command's algorithms must be read before the keys that depend on them exist.
func PeekProtectedPayload(b []byte) ([]byte, error) {
	m, err := eps.ParseSecurityProtectedMessage(b)
	if err != nil {
		return nil, err
	}

	return m.Payload, nil
}

func Decode(plain []byte) (*NASResponse, error) {
	resp := &NASResponse{RawHex: hex.EncodeToString(plain)}

	if len(plain) == 0 {
		return nil, fmt.Errorf("naseps: empty NAS message")
	}

	if plain[0]&0x0F == eps.PDESM {
		return decodeESM(plain, resp)
	}

	resp.SecurityHeaderType = SecurityHeaderTypeString(SecurityHeaderType(plain[0] >> 4))

	mt, err := eps.PeekMessageType(plain)
	if err != nil {
		return nil, fmt.Errorf("naseps: peek message type: %w", err)
	}

	resp.MessageType = emmMessageTypeName(mt)

	switch mt {
	case eps.MsgAuthenticationRequest:
		return resp, decodeAuthenticationRequest(plain, resp)
	case eps.MsgSecurityModeCommand:
		return resp, decodeSecurityModeCommand(plain, resp)
	case eps.MsgAttachAccept:
		return resp, decodeAttachAccept(plain, resp)
	case eps.MsgAttachReject:
		return resp, decodeAttachReject(plain, resp)
	case eps.MsgIdentityRequest:
		return resp, decodeIdentityRequest(plain, resp)
	case eps.MsgTrackingAreaUpdateAccept:
		return resp, decodeTAUAccept(plain, resp)
	case eps.MsgTrackingAreaUpdateReject, eps.MsgServiceReject:
		// Both are header(2) + EMM cause(1) (TS 24.301 §8.2.27, §8.2.24).
		if len(plain) >= 3 {
			c := int(plain[2])
			resp.EMMCause = &c
		}
	}

	return resp, nil
}

func emmMessageTypeName(t eps.MessageType) string {
	switch t {
	case eps.MsgAuthenticationRequest:
		return "authentication_request"
	case eps.MsgAuthenticationReject:
		return "authentication_reject"
	case eps.MsgSecurityModeCommand:
		return "security_mode_command"
	case eps.MsgAttachAccept:
		return "attach_accept"
	case eps.MsgAttachReject:
		return "attach_reject"
	case eps.MsgIdentityRequest:
		return "identity_request"
	case eps.MsgTrackingAreaUpdateAccept:
		return "tracking_area_update_accept"
	case eps.MsgTrackingAreaUpdateReject:
		return "tracking_area_update_reject"
	case eps.MsgServiceReject:
		return "service_reject"
	case eps.MsgEMMStatus:
		return "emm_status"
	case eps.MsgDetachRequest:
		return "detach_request"
	case eps.MsgDetachAccept:
		return "detach_accept"
	default:
		return fmt.Sprintf("emm_message_%#x", uint8(t))
	}
}

func decodeAuthenticationRequest(b []byte, resp *NASResponse) error {
	m, err := eps.ParseAuthenticationRequest(b)
	if err != nil {
		return err
	}

	resp.RAND = hex.EncodeToString(m.RAND[:])
	resp.AUTN = hex.EncodeToString(m.AUTN)
	ksi := int(m.NASKeySetIdentifier)
	resp.NASKeySetIdentifier = &ksi

	return nil
}

func decodeSecurityModeCommand(b []byte, resp *NASResponse) error {
	m, err := eps.ParseSecurityModeCommand(b)
	if err != nil {
		return err
	}

	ciph := int(m.CipheringAlgorithm)
	intg := int(m.IntegrityAlgorithm)
	imeisv := m.IMEISVRequested
	ksi := int(m.NASKeySetIdentifier)
	resp.SelectedCipheringAlgorithm = &ciph
	resp.SelectedIntegrityAlgorithm = &intg
	resp.NASKeySetIdentifier = &ksi
	resp.ReplayedUESecurityCapabilities = hex.EncodeToString(m.ReplayedUESecurityCapabilities)
	resp.IMEISVRequested = imeisv

	return nil
}

func decodeAttachAccept(b []byte, resp *NASResponse) error {
	m, err := eps.ParseAttachAccept(b)
	if err != nil {
		return err
	}

	result := int(m.EPSAttachResult)
	resp.EPSAttachResult = &result

	if len(m.TAIList) > 0 {
		resp.TAIList = hex.EncodeToString(m.TAIList)
	}

	if m.EMMCause != nil {
		c := int(*m.EMMCause)
		resp.EMMCause = &c
	}

	if m.GUTI != nil {
		resp.GUTI = &GUTIJSON{
			MCC:        m.GUTI.MCC,
			MNC:        m.GUTI.MNC,
			MMEGroupID: int(m.GUTI.MMEGroupID),
			MMECode:    int(m.GUTI.MMECode),
			MTMSI:      fmt.Sprintf("%08x", m.GUTI.MTMSI),
		}
	}

	if len(m.ESMMessageContainer) > 0 {
		// A decode error is non-fatal — the outer Attach Accept fields are already set.
		_ = decodeDefaultBearer(m.ESMMessageContainer, resp)
	}

	return nil
}

func decodeAttachReject(b []byte, resp *NASResponse) error {
	m, err := eps.ParseAttachReject(b)
	if err != nil {
		return err
	}

	cause := int(m.Cause)
	resp.EMMCause = &cause

	return nil
}

func decodeTAUAccept(b []byte, resp *NASResponse) error {
	m, err := eps.ParseTrackingAreaUpdateAccept(b)
	if err != nil {
		return err
	}

	result := int(m.EPSUpdateResult)
	resp.EPSUpdateResult = &result

	if m.EMMCause != nil {
		c := int(*m.EMMCause)
		resp.EMMCause = &c
	}

	if m.GUTI != nil {
		resp.GUTI = &GUTIJSON{
			MCC:        m.GUTI.MCC,
			MNC:        m.GUTI.MNC,
			MMEGroupID: int(m.GUTI.MMEGroupID),
			MMECode:    int(m.GUTI.MMECode),
			MTMSI:      fmt.Sprintf("%08x", m.GUTI.MTMSI),
		}
	}

	return nil
}

func decodeIdentityRequest(b []byte, resp *NASResponse) error {
	m, err := eps.ParseIdentityRequest(b)
	if err != nil {
		return err
	}

	t := int(m.IdentityType)
	resp.IdentityType = &t

	return nil
}
