// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import (
	"encoding/hex"
	"fmt"

	"github.com/ellanetworks/core/nas/eps"
)

// SecurityHeader returns the security-header type of a downlink NAS message so
// the caller knows whether to Unprotect it before decoding.
func SecurityHeader(b []byte) (SecurityHeaderType, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("naseps: empty NAS message")
	}

	if b[0]&0x0F != eps.PDEMM {
		return 0, fmt.Errorf("naseps: not an EMM message (PD %#x)", b[0]&0x0F)
	}

	return SecurityHeaderType(b[0] >> 4), nil
}

// PeekProtectedPayload returns the inner payload of a security-protected message
// without verifying the MAC. It is used to read the algorithms from a Security
// Mode Command (integrity-protected, not ciphered) before the NAS keys — which
// depend on those algorithms — can be derived.
func PeekProtectedPayload(b []byte) ([]byte, error) {
	m, err := eps.ParseSecurityProtectedMessage(b)
	if err != nil {
		return nil, err
	}

	return m.Payload, nil
}

// Decode decodes a plain (unprotected) downlink EMM message into JSON. The caller
// unwraps any security protection (Unprotect) first.
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

// decodeESM decodes a standalone EPS Session Management message (PD = ESM): the
// bearer-management messages exchanged for additional PDN connections.
func decodeESM(plain []byte, resp *NASResponse) (*NASResponse, error) {
	mt, err := eps.PeekESMMessageType(plain)
	if err != nil {
		return nil, fmt.Errorf("naseps: peek ESM message type: %w", err)
	}

	switch mt {
	case eps.MsgActivateDefaultEPSBearerContextRequest:
		resp.MessageType = "activate_default_eps_bearer_context_request"
		decodeDefaultBearer(plain, resp)
	case eps.MsgPDNConnectivityReject:
		resp.MessageType = "pdn_connectivity_reject"
		if m, err := eps.ParsePDNConnectivityReject(plain); err == nil {
			setESM(resp, int(m.EPSBearerIdentity), int(m.ProcedureTransactionIdentity), &m.ESMCause)
		}
	case eps.MsgPDNDisconnectReject:
		resp.MessageType = "pdn_disconnect_reject"
		if m, err := eps.ParsePDNDisconnectReject(plain); err == nil {
			setESM(resp, int(m.EPSBearerIdentity), int(m.ProcedureTransactionIdentity), &m.ESMCause)
		}
	case eps.MsgDeactivateEPSBearerContextRequest:
		resp.MessageType = "deactivate_eps_bearer_context_request"
		if m, err := eps.ParseDeactivateEPSBearerContextRequest(plain); err == nil {
			setESM(resp, int(m.EPSBearerIdentity), int(m.ProcedureTransactionIdentity), &m.ESMCause)
		}
	case eps.MsgModifyEPSBearerContextRequest:
		resp.MessageType = "modify_eps_bearer_context_request"
		if m, err := eps.ParseModifyEPSBearerContextRequest(plain); err == nil {
			ebi := int(m.EPSBearerIdentity)
			pti := int(m.ProcedureTransactionIdentity)
			resp.EPSBearerIdentity = &ebi
			resp.BearerPTI = &pti
		}
	default:
		resp.MessageType = fmt.Sprintf("esm_message_%#x", uint8(mt))
	}

	return resp, nil
}

// setESM records the EPS bearer identity, PTI, and ESM cause shared by the
// bearer-management reject and deactivation messages.
func setESM(resp *NASResponse, ebi, pti int, cause *uint8) {
	resp.EPSBearerIdentity = &ebi
	resp.BearerPTI = &pti

	if cause != nil {
		c := int(*cause)
		resp.ESMCause = &c
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

	// An EMM cause in an Attach Accept reports a partial result, e.g. #18 when a
	// combined attach gets EPS-only service (TS 24.301 §5.5.1.2.4).
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
		decodeDefaultBearer(m.ESMMessageContainer, resp)
	}

	return nil
}

// decodeDefaultBearer extracts the default-bearer parameters from the Activate
// Default EPS Bearer Context Request embedded in an Attach Accept. A decode error
// is non-fatal — the outer Attach Accept fields are already set.
func decodeDefaultBearer(container []byte, resp *NASResponse) {
	m, err := eps.ParseActivateDefaultEPSBearerContextRequest(container)
	if err != nil {
		return
	}

	ebi := int(m.EPSBearerIdentity)
	pti := int(m.ProcedureTransactionIdentity)
	resp.EPSBearerIdentity = &ebi
	resp.BearerPTI = &pti
	resp.PDNAddress = hex.EncodeToString(m.PDNAddress)
	resp.APN = hex.EncodeToString(m.AccessPointName)

	if m.ESMCause != nil {
		c := int(*m.ESMCause)
		resp.BearerESMCause = &c
	}
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
