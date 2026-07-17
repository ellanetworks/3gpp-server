// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import (
	"encoding/hex"
	"fmt"

	"github.com/ellanetworks/core/nas/eps"
)

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

	mt, err := eps.PeekMessageType(plain)
	if err != nil {
		return nil, fmt.Errorf("naseps: peek message type: %w", err)
	}

	switch mt {
	case eps.MsgAuthenticationRequest:
		resp.MessageType = "authentication_request"
		return resp, decodeAuthenticationRequest(plain, resp)
	case eps.MsgAuthenticationReject:
		resp.MessageType = "authentication_reject"
		return resp, nil
	case eps.MsgSecurityModeCommand:
		resp.MessageType = "security_mode_command"
		return resp, decodeSecurityModeCommand(plain, resp)
	case eps.MsgAttachAccept:
		resp.MessageType = "attach_accept"
		return resp, decodeAttachAccept(plain, resp)
	case eps.MsgAttachReject:
		resp.MessageType = "attach_reject"
		return resp, decodeAttachReject(plain, resp)
	case eps.MsgIdentityRequest:
		resp.MessageType = "identity_request"
		return resp, decodeIdentityRequest(plain, resp)
	case eps.MsgTrackingAreaUpdateAccept:
		resp.MessageType = "tracking_area_update_accept"
		return resp, decodeTAUAccept(plain, resp)
	case eps.MsgTrackingAreaUpdateReject:
		resp.MessageType = "tracking_area_update_reject"
		// TAU REJECT is header(2) + EMM cause(1) (TS 24.301 §8.2.27).
		if len(plain) >= 3 {
			c := int(plain[2])
			resp.EMMCause = &c
		}

		return resp, nil
	case eps.MsgServiceReject:
		resp.MessageType = "service_reject"
		// SERVICE REJECT is header(2) + EMM cause(1) (TS 24.301 §8.2.24).
		if len(plain) >= 3 {
			c := int(plain[2])
			resp.EMMCause = &c
		}

		return resp, nil
	case eps.MsgEMMStatus:
		resp.MessageType = "emm_status"
		return resp, nil
	case eps.MsgDetachRequest:
		resp.MessageType = "detach_request"
		return resp, nil
	case eps.MsgDetachAccept:
		resp.MessageType = "detach_accept"
		return resp, nil
	default:
		resp.MessageType = fmt.Sprintf("emm_message_%#x", uint8(mt))
		return resp, nil
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
	resp.KSI = &ksi

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
	resp.CipheringAlgorithm = &ciph
	resp.IntegrityAlgorithm = &intg
	resp.ReplayedUESecurityCapabilities = hex.EncodeToString(m.ReplayedUESecurityCapabilities)
	resp.IMEISVRequested = &imeisv

	return nil
}

func decodeAttachAccept(b []byte, resp *NASResponse) error {
	m, err := eps.ParseAttachAccept(b)
	if err != nil {
		return err
	}

	result := int(m.EPSAttachResult)
	resp.EPSAttachResult = &result

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
