// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ellanetworks/core/nas/common"
	"github.com/ellanetworks/core/nas/eps"
)

// EPS update types (TS 24.301 §9.9.3.14).
const (
	EPSUpdateTypeTA               uint8 = 0
	EPSUpdateTypeCombinedTALA     uint8 = 1
	EPSUpdateTypeCombinedTALAImsi uint8 = 2
	EPSUpdateTypePeriodic         uint8 = 3
)

func encodeGUTIIdentity(guti GUTIParams) ([]byte, error) {
	plmn, err := common.EncodePLMN(guti.MCC, guti.MNC)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 11)
	out[0] = 0xF0 | 0x06 // spare 1111, even, type-of-identity GUTI (110)
	copy(out[1:4], plmn[:])
	binary.BigEndian.PutUint16(out[4:6], guti.MMEGroupID)
	out[6] = guti.MMECode
	binary.BigEndian.PutUint32(out[7:11], guti.MTMSI)

	return out, nil
}

// BuildTrackingAreaUpdateRequest builds a plain TAU REQUEST (TS 24.301 §8.2.29).
func BuildTrackingAreaUpdateRequest(updateType uint8, activeFlag bool, ksi uint8, guti GUTIParams) ([]byte, error) {
	gutiID, err := encodeGUTIIdentity(guti)
	if err != nil {
		return nil, err
	}

	var w common.Writer

	w.U8(uint8(eps.SHTPlain)<<4 | eps.PDEMM)
	w.U8(uint8(eps.MsgTrackingAreaUpdateRequest))

	active := uint8(0)
	if activeFlag {
		active = 0x08
	}

	w.U8(ksi<<4 | active | updateType&0x07) // NAS KSI | active flag | EPS update type

	if err := w.LV(gutiID); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// BuildTrackingAreaUpdateComplete builds a plain TAU COMPLETE (TS 24.301 §8.2.28).
func BuildTrackingAreaUpdateComplete() ([]byte, error) {
	return (&eps.TrackingAreaUpdateComplete{}).Marshal()
}

// EEA0/1/2 and EIA0/1/2; bit 7 = algorithm 0, bit 6 = 1, bit 5 = 2 (TS 24.301 §9.9.3.34).
var DefaultUENetworkCapability = []byte{0xE0, 0xE0}

// PDN types (TS 24.301 §9.9.4.10).
const (
	PDNTypeIPv4   uint8 = 1
	PDNTypeIPv6   uint8 = 2
	PDNTypeIPv4v6 uint8 = 3
)

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

// GUTIParams identifies a GUTI mobile identity (TS 24.301 §9.9.3.12).
type GUTIParams struct {
	MCC, MNC   string
	MMEGroupID uint16
	MMECode    uint8
	MTMSI      uint32
}

type AttachRequestParams struct {
	IMSI                string
	GUTI                *GUTIParams
	AttachType          uint8
	NASKeySetIdentifier uint8
	UENetworkCapability []byte
	ESMContainer        []byte
}

// BuildAttachRequest builds a plain ATTACH REQUEST (TS 24.301 §8.2.4).
func BuildAttachRequest(p AttachRequestParams) ([]byte, error) {
	cap := p.UENetworkCapability
	if cap == nil {
		cap = DefaultUENetworkCapability
	}

	attachType := p.AttachType
	if attachType == 0 {
		attachType = eps.AttachTypeEPS
	}

	id := eps.EPSMobileIdentity{Type: eps.IdentityIMSI, Digits: p.IMSI}
	if p.GUTI != nil {
		id = eps.EPSMobileIdentity{
			Type:       eps.IdentityGUTI,
			MCC:        p.GUTI.MCC,
			MNC:        p.GUTI.MNC,
			MMEGroupID: p.GUTI.MMEGroupID,
			MMECode:    p.GUTI.MMECode,
			MTMSI:      p.GUTI.MTMSI,
		}
	}

	m := &eps.AttachRequest{
		EPSAttachType:       attachType,
		NASKeySetIdentifier: p.NASKeySetIdentifier,
		EPSMobileIdentity:   id,
		UENetworkCapability: cap,
		ESMMessageContainer: p.ESMContainer,
	}

	return m.Marshal()
}

// BuildIdentityResponse builds a plain IDENTITY RESPONSE carrying the IMSI as a mobile identity (TS 24.301 §8.2.19, TS 24.008 §10.5.1.4).
func BuildIdentityResponse(imsi string) ([]byte, error) {
	if imsi == "" || imsi[0] < '0' || imsi[0] > '9' {
		return nil, fmt.Errorf("naseps: invalid IMSI %q", imsi)
	}

	rest, err := common.EncodeTBCD(imsi[1:])
	if err != nil {
		return nil, err
	}

	oddEven := byte(len(imsi) & 1)
	// octet 1: first digit | odd/even | type-of-identity = IMSI (001).
	mobid := append([]byte{(imsi[0]-'0')<<4 | oddEven<<3 | 1}, rest...)

	return (&eps.IdentityResponse{MobileIdentity: mobid}).Marshal()
}

// BuildAuthenticationResponse builds a plain AUTHENTICATION RESPONSE (TS 24.301 §8.2.8).
func BuildAuthenticationResponse(res []byte) ([]byte, error) {
	return (&eps.AuthenticationResponse{RES: res}).Marshal()
}

// BuildAuthenticationFailure builds a plain AUTHENTICATION FAILURE (TS 24.301 §8.2.5).
func BuildAuthenticationFailure(cause uint8, auts []byte) ([]byte, error) {
	return (&eps.AuthenticationFailure{Cause: cause, AUTS: auts}).Marshal()
}

// BuildSecurityModeComplete builds a plain SECURITY MODE COMPLETE (TS 24.301 §8.2.21).
func BuildSecurityModeComplete(imeisv []byte) ([]byte, error) {
	return (&eps.SecurityModeComplete{IMEISV: imeisv}).Marshal()
}

// BuildSecurityModeReject builds a plain SECURITY MODE REJECT (TS 24.301 §8.2.22).
func BuildSecurityModeReject(cause uint8) ([]byte, error) {
	return (&eps.SecurityModeReject{Cause: cause}).Marshal()
}

// BuildActivateDefaultEPSBearerContextAccept builds an ACTIVATE DEFAULT EPS BEARER CONTEXT ACCEPT (TS 24.301 §8.3.2).
func BuildActivateDefaultEPSBearerContextAccept(ebi, pti uint8) ([]byte, error) {
	return (&eps.ActivateDefaultEPSBearerContextAccept{
		EPSBearerIdentity:            ebi,
		ProcedureTransactionIdentity: pti,
	}).Marshal()
}

// BuildAttachComplete builds a plain ATTACH COMPLETE (TS 24.301 §8.2.2).
func BuildAttachComplete(esmContainer []byte) ([]byte, error) {
	return (&eps.AttachComplete{ESMMessageContainer: esmContainer}).Marshal()
}

// BuildServiceRequest builds the 4-octet SERVICE REQUEST: SHT/PD, KSI | 5-bit truncated COUNT, then a short MAC over those two octets (TS 24.301 §8.2.25).
func BuildServiceRequest(ksi uint8, count uint32, knasInt [16]byte, eia uint8) ([]byte, error) {
	integ, err := integrityFor(eia)
	if err != nil {
		return nil, err
	}

	octet0 := uint8(eps.SHTServiceRequest)<<4 | eps.PDEMM
	octet1 := ksi<<5 | uint8(count)&0x1F

	mac, err := eps.ServiceRequestShortMAC([]byte{octet0, octet1}, knasInt, count, common.DirectionUplink, integ)
	if err != nil {
		return nil, err
	}

	return []byte{octet0, octet1, mac[0], mac[1]}, nil
}

// BuildDetachRequest builds a UE-originating plain DETACH REQUEST (TS 24.301 §8.2.11).
func BuildDetachRequest(switchOff bool, ksi uint8, guti GUTIParams) ([]byte, error) {
	return (&eps.DetachRequestUE{
		SwitchOff:           switchOff,
		TypeOfDetach:        eps.DetachTypeEPS,
		NASKeySetIdentifier: ksi,
		EPSMobileIdentity: eps.EPSMobileIdentity{
			Type:       eps.IdentityGUTI,
			MCC:        guti.MCC,
			MNC:        guti.MNC,
			MMEGroupID: guti.MMEGroupID,
			MMECode:    guti.MMECode,
			MTMSI:      guti.MTMSI,
		},
	}).Marshal()
}
