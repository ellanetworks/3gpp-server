// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

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

type TrackingAreaUpdateRequestParams struct {
	UpdateType uint8
	ActiveFlag bool
	KSI        uint8
	GUTI       GUTIParams
}

// BuildTrackingAreaUpdateRequest builds a plain TAU REQUEST (TS 24.301 §8.2.29).
func BuildTrackingAreaUpdateRequest(p TrackingAreaUpdateRequestParams) ([]byte, error) {
	gutiID, err := encodeGUTIIdentity(p.GUTI)
	if err != nil {
		return nil, err
	}

	var w common.Writer

	w.U8(uint8(eps.SHTPlain)<<4 | eps.PDEMM)
	w.U8(uint8(eps.MsgTrackingAreaUpdateRequest))

	active := uint8(0)
	if p.ActiveFlag {
		active = 0x08
	}

	w.U8(p.KSI<<4 | active | p.UpdateType&0x07) // NAS KSI | active flag | EPS update type

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
	Overrides           *AttachRequestOverrides
}

// AttachRequestOverrides carries the optional ATTACH REQUEST IEs the EPS codec
// can express (TS 24.301 §8.2.4), each as a hex string; nil leaves the IE absent.
type AttachRequestOverrides struct {
	UENetworkCapability *string
	MSNetworkCapability *string
	DRXParameter        *string
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

	if o := p.Overrides; o != nil {
		if err := applyHexOverride(o.UENetworkCapability, &m.UENetworkCapability); err != nil {
			return nil, fmt.Errorf("ue_network_capability: %w", err)
		}

		if err := applyHexOverride(o.MSNetworkCapability, &m.MSNetworkCapability); err != nil {
			return nil, fmt.Errorf("ms_network_capability: %w", err)
		}

		if err := applyHexOverride(o.DRXParameter, &m.DRXParameter); err != nil {
			return nil, fmt.Errorf("drx_parameter: %w", err)
		}
	}

	return m.Marshal()
}

func applyHexOverride(hexStr *string, dst *[]byte) error {
	if hexStr == nil {
		return nil
	}

	b, err := hex.DecodeString(*hexStr)
	if err != nil {
		return err
	}

	*dst = b

	return nil
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
// An empty imeisv omits the IMEISV mobile identity.
func BuildSecurityModeComplete(imeisv string) ([]byte, error) {
	var mobid []byte

	if imeisv != "" {
		var err error
		if mobid, err = imeisvMobileIdentity(imeisv); err != nil {
			return nil, err
		}
	}

	return (&eps.SecurityModeComplete{IMEISV: mobid}).Marshal()
}

// imeisvMobileIdentity encodes 16 IMEISV digits as a mobile identity value:
// first digit | odd/even | type-of-identity IMEISV (011), then the remaining
// digits TBCD-packed with a 1111 end mark (TS 24.008 §10.5.1.4).
func imeisvMobileIdentity(imeisv string) ([]byte, error) {
	if len(imeisv) != 16 {
		return nil, fmt.Errorf("naseps: IMEISV must be 16 digits")
	}

	rest, err := common.EncodeTBCD(imeisv[1:])
	if err != nil {
		return nil, err
	}

	oddEven := byte(len(imeisv) & 1)

	return append([]byte{(imeisv[0]-'0')<<4 | oddEven<<3 | 3}, rest...), nil
}

// BuildSecurityModeReject builds a plain SECURITY MODE REJECT (TS 24.301 §8.2.22).
func BuildSecurityModeReject(cause uint8) ([]byte, error) {
	return (&eps.SecurityModeReject{Cause: cause}).Marshal()
}

// BuildAttachComplete builds a plain ATTACH COMPLETE (TS 24.301 §8.2.2).
func BuildAttachComplete(esmContainer []byte) ([]byte, error) {
	return (&eps.AttachComplete{ESMMessageContainer: esmContainer}).Marshal()
}

type ServiceRequestParams struct {
	KSI     uint8
	Count   uint32
	KnasInt [16]byte
	EIA     uint8
}

// BuildServiceRequest builds the 4-octet SERVICE REQUEST: SHT/PD, KSI | 5-bit truncated COUNT, then a short MAC over those two octets (TS 24.301 §8.2.25).
func BuildServiceRequest(p ServiceRequestParams) ([]byte, error) {
	integ, err := integrityFor(p.EIA)
	if err != nil {
		return nil, err
	}

	octet0 := uint8(eps.SHTServiceRequest)<<4 | eps.PDEMM
	octet1 := p.KSI<<5 | uint8(p.Count)&0x1F

	mac, err := eps.ServiceRequestShortMAC([]byte{octet0, octet1}, p.KnasInt, p.Count, common.DirectionUplink, integ)
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
