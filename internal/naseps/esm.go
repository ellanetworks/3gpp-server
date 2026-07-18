// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ellanetworks/core/nas/eps"
)

// PDN types (TS 24.301 §9.9.4.10).
const (
	PDNTypeIPv4   uint8 = 1
	PDNTypeIPv6   uint8 = 2
	PDNTypeIPv4v6 uint8 = 3
)

// ESM message types absent from the eps codec (TS 24.301 §9.8).
const (
	msgBearerResourceAllocationRequest   uint8 = 0xD4
	msgBearerResourceAllocationReject    uint8 = 0xD5
	msgBearerResourceModificationRequest uint8 = 0xD6
	msgBearerResourceModificationReject  uint8 = 0xD7
)

// The half octet pairs the default bearer (EPS bearer identity 5) with a spare half octet (TS 24.301 §9.9.4.6).
const bearerResourceLinkedEBIHalfOctet uint8 = 0x05

// BuildPDNConnectivityRequest builds an ESM PDN CONNECTIVITY REQUEST (TS 24.301 §8.3.20).
func BuildPDNConnectivityRequest(pti, pdnType uint8) ([]byte, error) {
	return BuildPDNConnectivityRequestWith(PDNConnectivityParams{PTI: pti, PDNType: pdnType})
}

// PDNConnectivityParams drives a PDN CONNECTIVITY REQUEST; EPSBearerIdentity is 0 in a valid request, non-zero exercising the invalid-EBI path (TS 24.301 §7.3.2).
type PDNConnectivityParams struct {
	PTI               uint8
	EPSBearerIdentity uint8
	PDNType           uint8
	APN               string
}

// BuildPDNConnectivityRequestWith builds a PDN CONNECTIVITY REQUEST (TS 24.301 §8.3.20).
func BuildPDNConnectivityRequestWith(p PDNConnectivityParams) ([]byte, error) {
	pdnType := p.PDNType
	if pdnType == 0 {
		pdnType = PDNTypeIPv4
	}

	m := &eps.PDNConnectivityRequest{
		EPSBearerIdentity:            p.EPSBearerIdentity,
		ProcedureTransactionIdentity: p.PTI,
		RequestType:                  1, // initial request
		PDNType:                      pdnType,
		AccessPointName:              encodeAPN(p.APN),
	}

	return m.Marshal()
}

// encodeAPN emits each label prefixed by its length octet (TS 23.003 §9.1).
func encodeAPN(apn string) []byte {
	if apn == "" {
		return nil
	}

	var out []byte
	for _, label := range strings.Split(apn, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}

	return out
}

// BuildPDNDisconnectRequest builds a PDN DISCONNECT REQUEST (TS 24.301 §8.3.19).
func BuildPDNDisconnectRequest(pti, linkedEBI uint8) ([]byte, error) {
	return (&eps.PDNDisconnectRequest{
		EPSBearerIdentity:            0,
		ProcedureTransactionIdentity: pti,
		LinkedEPSBearerIdentity:      linkedEBI,
	}).Marshal()
}

// BuildDeactivateEPSBearerContextAccept builds a DEACTIVATE EPS BEARER CONTEXT ACCEPT (TS 24.301 §8.3.8).
func BuildDeactivateEPSBearerContextAccept(ebi, pti uint8) ([]byte, error) {
	return (&eps.DeactivateEPSBearerContextAccept{
		EPSBearerIdentity:            ebi,
		ProcedureTransactionIdentity: pti,
	}).Marshal()
}

// BuildModifyEPSBearerContextAccept builds a MODIFY EPS BEARER CONTEXT ACCEPT (TS 24.301 §8.3.10).
func BuildModifyEPSBearerContextAccept(ebi, pti uint8) ([]byte, error) {
	return (&eps.ModifyEPSBearerContextAccept{
		EPSBearerIdentity:            ebi,
		ProcedureTransactionIdentity: pti,
	}).Marshal()
}

// BuildESMStatus builds an ESM STATUS (TS 24.301 §8.3.15).
func BuildESMStatus(ebi, pti, cause uint8) ([]byte, error) {
	return (&eps.ESMStatus{
		EPSBearerIdentity:            ebi,
		ProcedureTransactionIdentity: pti,
		ESMCause:                     cause,
	}).Marshal()
}

// BuildActivateDefaultEPSBearerContextAccept builds an ACTIVATE DEFAULT EPS BEARER CONTEXT ACCEPT (TS 24.301 §8.3.2).
func BuildActivateDefaultEPSBearerContextAccept(ebi, pti uint8) ([]byte, error) {
	return (&eps.ActivateDefaultEPSBearerContextAccept{
		EPSBearerIdentity:            ebi,
		ProcedureTransactionIdentity: pti,
	}).Marshal()
}

// BuildBearerResourceAllocationRequest builds a BEARER RESOURCE ALLOCATION REQUEST (TS 24.301 §8.3.8).
func BuildBearerResourceAllocationRequest(pti uint8) ([]byte, error) {
	out := []byte{eps.PDESM, pti, msgBearerResourceAllocationRequest, bearerResourceLinkedEBIHalfOctet}
	out = append(out, bearerResourceTAD()...)
	out = append(out, requiredTrafficFlowQoS()...)

	return out, nil
}

// BuildBearerResourceModificationRequest builds a BEARER RESOURCE MODIFICATION REQUEST (TS 24.301 §8.3.10).
func BuildBearerResourceModificationRequest(pti uint8) ([]byte, error) {
	out := []byte{eps.PDESM, pti, msgBearerResourceModificationRequest, bearerResourceLinkedEBIHalfOctet}
	out = append(out, bearerResourceTAD()...)

	return out, nil
}

// BuildESMInformationResponse builds an ESM INFORMATION RESPONSE (TS 24.301 §8.3.14).
func BuildESMInformationResponse(pti uint8) ([]byte, error) {
	return (&eps.ESMInformationResponse{
		EPSBearerIdentity:            0,
		ProcedureTransactionIdentity: pti,
	}).Marshal()
}

// bearerResourceTAD is a create-new-TFT traffic flow aggregate description with a single bidirectional IPv4 packet filter (TS 24.008 §10.5.6.12).
func bearerResourceTAD() []byte {
	const (
		createNewTFTOneFilter   uint8 = 0x21
		bidirectionalFilterZero uint8 = 0x30
		ipv4RemoteAddressType   uint8 = 0x10
	)

	tft := []byte{
		createNewTFTOneFilter,
		bidirectionalFilterZero,
		0x00, // evaluation precedence
		0x09, // packet filter contents length
		ipv4RemoteAddressType,
		0, 0, 0, 0, // address
		0, 0, 0, 0, // mask
	}

	return append([]byte{byte(len(tft))}, tft...)
}

// requiredTrafficFlowQoS is an EPS quality of service carrying only the QCI (TS 24.301 §9.9.4.3).
func requiredTrafficFlowQoS() []byte {
	const qci uint8 = 9

	return []byte{0x01, qci}
}

func esmMessageTypeName(t eps.ESMMessageType) string {
	switch t {
	case eps.MsgActivateDefaultEPSBearerContextRequest:
		return "activate_default_eps_bearer_context_request"
	case eps.MsgPDNConnectivityReject:
		return "pdn_connectivity_reject"
	case eps.MsgPDNDisconnectReject:
		return "pdn_disconnect_reject"
	case eps.MsgDeactivateEPSBearerContextRequest:
		return "deactivate_eps_bearer_context_request"
	case eps.MsgModifyEPSBearerContextRequest:
		return "modify_eps_bearer_context_request"
	case eps.MsgESMStatus:
		return "esm_status"
	case eps.ESMMessageType(msgBearerResourceAllocationReject):
		return "bearer_resource_allocation_reject"
	case eps.ESMMessageType(msgBearerResourceModificationReject):
		return "bearer_resource_modification_reject"
	default:
		return fmt.Sprintf("esm_message_%#x", uint8(t))
	}
}

func decodeESM(plain []byte, resp *NASResponse) (*NASResponse, error) {
	mt, err := eps.PeekESMMessageType(plain)
	if err != nil {
		return nil, fmt.Errorf("naseps: peek ESM message type: %w", err)
	}

	resp.MessageType = esmMessageTypeName(mt)

	switch mt {
	case eps.MsgActivateDefaultEPSBearerContextRequest:
		if err := decodeDefaultBearer(plain, resp); err != nil {
			return nil, fmt.Errorf("naseps: parse activate default EPS bearer context request: %w", err)
		}
	case eps.MsgPDNConnectivityReject:
		m, err := eps.ParsePDNConnectivityReject(plain)
		if err != nil {
			return nil, fmt.Errorf("naseps: parse PDN connectivity reject: %w", err)
		}

		setESM(resp, int(m.EPSBearerIdentity), int(m.ProcedureTransactionIdentity), &m.ESMCause)
	case eps.MsgPDNDisconnectReject:
		m, err := eps.ParsePDNDisconnectReject(plain)
		if err != nil {
			return nil, fmt.Errorf("naseps: parse PDN disconnect reject: %w", err)
		}

		setESM(resp, int(m.EPSBearerIdentity), int(m.ProcedureTransactionIdentity), &m.ESMCause)
	case eps.MsgDeactivateEPSBearerContextRequest:
		m, err := eps.ParseDeactivateEPSBearerContextRequest(plain)
		if err != nil {
			return nil, fmt.Errorf("naseps: parse deactivate EPS bearer context request: %w", err)
		}

		setESM(resp, int(m.EPSBearerIdentity), int(m.ProcedureTransactionIdentity), &m.ESMCause)
	case eps.MsgModifyEPSBearerContextRequest:
		m, err := eps.ParseModifyEPSBearerContextRequest(plain)
		if err != nil {
			return nil, fmt.Errorf("naseps: parse modify EPS bearer context request: %w", err)
		}

		ebi := int(m.EPSBearerIdentity)
		pti := int(m.ProcedureTransactionIdentity)
		resp.EPSBearerIdentity = &ebi
		resp.BearerPTI = &pti

		if len(m.APNAMBR) > 0 {
			resp.APNAMBR = hex.EncodeToString(m.APNAMBR)
		}
	case eps.MsgESMStatus:
		m, err := eps.ParseESMStatus(plain)
		if err != nil {
			return nil, fmt.Errorf("naseps: parse ESM status: %w", err)
		}

		setESM(resp, int(m.EPSBearerIdentity), int(m.ProcedureTransactionIdentity), &m.ESMCause)
	case eps.ESMMessageType(msgBearerResourceAllocationReject):
		if err := decodeBearerResourceReject(plain, resp); err != nil {
			return nil, fmt.Errorf("naseps: parse bearer resource allocation reject: %w", err)
		}
	case eps.ESMMessageType(msgBearerResourceModificationReject):
		if err := decodeBearerResourceReject(plain, resp); err != nil {
			return nil, fmt.Errorf("naseps: parse bearer resource modification reject: %w", err)
		}
	}

	return resp, nil
}

// The ESM cause is octet 4 of both bearer resource reject messages, which the eps codec does not parse (TS 24.301 §8.3.7, §8.3.9).
func decodeBearerResourceReject(plain []byte, resp *NASResponse) error {
	if len(plain) < 4 {
		return fmt.Errorf("bearer resource reject is %d octets, want at least 4", len(plain))
	}

	cause := plain[3]
	setESM(resp, int(plain[0]>>4), int(plain[1]), &cause)

	return nil
}

func setESM(resp *NASResponse, ebi, pti int, cause *uint8) {
	resp.EPSBearerIdentity = &ebi
	resp.BearerPTI = &pti

	if cause != nil {
		c := int(*cause)
		resp.ESMCause = &c
	}
}

func decodeDefaultBearer(container []byte, resp *NASResponse) error {
	m, err := eps.ParseActivateDefaultEPSBearerContextRequest(container)
	if err != nil {
		return err
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

	return nil
}
