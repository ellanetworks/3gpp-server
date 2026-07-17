// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

type RegistrationRequestOpts struct {
	RegistrationType uint8
	Suci             nasType.MobileIdentity5GS
	Guti             *nasType.GUTI5G
	SecurityCap      *nasType.UESecurityCapability
	NgKsi            uint8

	Overrides *NASRequest
}

// BuildRegistrationRequest builds a plain REGISTRATION REQUEST (TS 24.501 §8.2.6).
func BuildRegistrationRequest(opts *RegistrationRequestOpts) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationRequest)

	registrationRequest := nasMessage.NewRegistrationRequest(0)
	registrationRequest.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	registrationRequest.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	registrationRequest.SetSpareHalfOctet(0x00)
	registrationRequest.SetMessageType(nas.MsgTypeRegistrationRequest)

	ngKsi := opts.NgKsi
	if opts.Overrides != nil && opts.Overrides.NgKSI != nil {
		ngKsi = *opts.Overrides.NgKSI
	}
	registrationRequest.NgksiAndRegistrationType5GS.SetNasKeySetIdentifiler(ngKsi)

	regType := opts.RegistrationType
	if regType == 0 {
		regType = RegistrationTypeInitial
	}
	registrationRequest.SetRegistrationType5GS(regType)

	if opts.Overrides != nil && opts.Overrides.MobileIdentityOverride != nil {
		idBytes, err := hex.DecodeString(*opts.Overrides.MobileIdentityOverride)
		if err != nil {
			return nil, fmt.Errorf("nas: decode mobile_identity_override: %w", err)
		}
		registrationRequest.MobileIdentity5GS = nasType.MobileIdentity5GS{
			Len:    uint16(len(idBytes)),
			Buffer: idBytes,
		}
	} else if opts.Guti != nil {
		registrationRequest.MobileIdentity5GS = nasType.MobileIdentity5GS{
			Iei:    opts.Guti.Iei,
			Len:    opts.Guti.Len,
			Buffer: opts.Guti.Octet[:],
		}
	} else {
		registrationRequest.MobileIdentity5GS = opts.Suci
	}

	if opts.Overrides != nil && opts.Overrides.UESecurityCapabilityOverride != nil {
		capBytes, err := hex.DecodeString(*opts.Overrides.UESecurityCapabilityOverride)
		if err != nil {
			return nil, fmt.Errorf("nas: decode ue_security_capability: %w", err)
		}
		registrationRequest.UESecurityCapability = nasType.NewUESecurityCapability(nasMessage.RegistrationRequestUESecurityCapabilityType)
		registrationRequest.UESecurityCapability.SetLen(uint8(len(capBytes)))
		copy(registrationRequest.UESecurityCapability.Buffer[:], capBytes)
	} else {
		registrationRequest.UESecurityCapability = opts.SecurityCap
	}

	forBit := uint8(1)
	if opts.Overrides != nil && opts.Overrides.FollowOnRequest != nil {
		forBit = *opts.Overrides.FollowOnRequest
	}
	registrationRequest.SetFOR(forBit)

	if opts.Overrides != nil {
		applyRegistrationRequestOverrides(registrationRequest, opts.Overrides)
	}

	m.RegistrationRequest = registrationRequest

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode error: %w", err)
	}

	return data.Bytes(), nil
}

func applyRegistrationRequestOverrides(rr *nasMessage.RegistrationRequest, req *NASRequest) {
	if req.NonCurrentNativeNASKSI != nil {
		rr.NoncurrentNativeNASKeySetIdentifier = new(nasType.NoncurrentNativeNASKeySetIdentifier)
		rr.NoncurrentNativeNASKeySetIdentifier.SetIei(nasMessage.RegistrationRequestNoncurrentNativeNASKeySetIdentifierType)
		rr.NoncurrentNativeNASKeySetIdentifier.SetNasKeySetIdentifiler(*req.NonCurrentNativeNASKSI & 0x07)
		rr.SetTsc((*req.NonCurrentNativeNASKSI >> 3) & 0x01)
	}

	if req.Capability5GMM != nil {
		if capBytes, err := hex.DecodeString(*req.Capability5GMM); err == nil && len(capBytes) > 0 {
			rr.Capability5GMM = &nasType.Capability5GMM{
				Iei: nasMessage.RegistrationRequestCapability5GMMType,
				Len: uint8(len(capBytes)),
			}
			copy(rr.Capability5GMM.Octet[:], capBytes)
		}
	}

	if len(req.RequestedNSSAI) > 0 {
		var buf []byte
		for _, s := range req.RequestedNSSAI {
			sst := byte(s.SST)
			if s.SD != "" {
				sdBytes, err := hex.DecodeString(s.SD)
				if err == nil && len(sdBytes) == 3 {
					buf = append(buf, 4)
					buf = append(buf, sst)
					buf = append(buf, sdBytes...)
					continue
				}
			}
			buf = append(buf, 1, sst)
		}
		rr.RequestedNSSAI = nasType.NewRequestedNSSAI(nasMessage.RegistrationRequestRequestedNSSAIType)
		rr.RequestedNSSAI.SetLen(uint8(len(buf)))
		copy(rr.RequestedNSSAI.Buffer, buf)
	}

	if req.LastVisitedRegisteredTAI != nil {
		if taiBytes, err := hex.DecodeString(*req.LastVisitedRegisteredTAI); err == nil && len(taiBytes) == 6 {
			rr.LastVisitedRegisteredTAI = nasType.NewLastVisitedRegisteredTAI(nasMessage.RegistrationRequestLastVisitedRegisteredTAIType)
			copy(rr.LastVisitedRegisteredTAI.Octet[:], taiBytes)
		}
	}

	if req.S1UENetworkCapability != nil {
		if capBytes, err := hex.DecodeString(*req.S1UENetworkCapability); err == nil && len(capBytes) > 0 {
			rr.S1UENetworkCapability = nasType.NewS1UENetworkCapability(nasMessage.RegistrationRequestS1UENetworkCapabilityType)
			rr.S1UENetworkCapability.SetLen(uint8(len(capBytes)))
			copy(rr.S1UENetworkCapability.Buffer, capBytes)
		}
	}

	if req.UplinkDataStatus != nil {
		if statusBytes, err := hex.DecodeString(*req.UplinkDataStatus); err == nil && len(statusBytes) >= 2 {
			rr.UplinkDataStatus = new(nasType.UplinkDataStatus)
			rr.UplinkDataStatus.SetIei(nasMessage.RegistrationRequestUplinkDataStatusType)
			rr.UplinkDataStatus.SetLen(uint8(len(statusBytes)))
			rr.UplinkDataStatus.Buffer = statusBytes
		}
	}

	if req.PDUSessionStatus != nil {
		if statusBytes, err := hex.DecodeString(*req.PDUSessionStatus); err == nil && len(statusBytes) >= 2 {
			rr.PDUSessionStatus = new(nasType.PDUSessionStatus)
			rr.PDUSessionStatus.SetIei(nasMessage.RegistrationRequestPDUSessionStatusType)
			rr.PDUSessionStatus.SetLen(uint8(len(statusBytes)))
			rr.PDUSessionStatus.Buffer = statusBytes
		}
	}

	if req.MICOIndication != nil {
		rr.MICOIndication = nasType.NewMICOIndication(nasMessage.RegistrationRequestMICOIndicationType)
		rr.SetRAAI(*req.MICOIndication & 0x01)
	}

	if req.UEStatus != nil {
		rr.UEStatus = nasType.NewUEStatus(nasMessage.RegistrationRequestUEStatusType)
		rr.UEStatus.SetLen(1)
		rr.SetN1ModeReg((*req.UEStatus >> 1) & 0x01)
		rr.SetS1ModeReg(*req.UEStatus & 0x01)
	}

	if req.AdditionalGUTI != nil {
		if gutiBytes, err := hex.DecodeString(*req.AdditionalGUTI); err == nil && len(gutiBytes) > 0 && len(gutiBytes) <= 11 {
			rr.AdditionalGUTI = nasType.NewAdditionalGUTI(nasMessage.RegistrationRequestAdditionalGUTIType)
			rr.AdditionalGUTI.SetLen(uint16(len(gutiBytes)))
			copy(rr.AdditionalGUTI.Octet[:], gutiBytes)
		}
	}

	if req.AllowedPDUSessionStatus != nil {
		if statusBytes, err := hex.DecodeString(*req.AllowedPDUSessionStatus); err == nil && len(statusBytes) >= 2 {
			rr.AllowedPDUSessionStatus = nasType.NewAllowedPDUSessionStatus(nasMessage.RegistrationRequestAllowedPDUSessionStatusType)
			rr.AllowedPDUSessionStatus.SetLen(uint8(len(statusBytes)))
			rr.AllowedPDUSessionStatus.Buffer = statusBytes
		}
	}

	if req.UEsUsageSetting != nil {
		rr.UesUsageSetting = nasType.NewUesUsageSetting(nasMessage.RegistrationRequestUesUsageSettingType)
		rr.UesUsageSetting.SetLen(1)
		rr.SetUesUsageSetting(*req.UEsUsageSetting & 0x01)
	}

	if req.RequestedDRXParameters != nil {
		rr.RequestedDRXParameters = nasType.NewRequestedDRXParameters(nasMessage.RegistrationRequestRequestedDRXParametersType)
		rr.RequestedDRXParameters.SetLen(1)
		rr.SetDRXValue(*req.RequestedDRXParameters)
	}

	if req.EPSNASMessageContainer != nil {
		if epsBytes, err := hex.DecodeString(*req.EPSNASMessageContainer); err == nil {
			rr.EPSNASMessageContainer = nasType.NewEPSNASMessageContainer(nasMessage.RegistrationRequestEPSNASMessageContainerType)
			rr.EPSNASMessageContainer.SetLen(uint16(len(epsBytes)))
			copy(rr.EPSNASMessageContainer.Buffer, epsBytes)
		}
	}

	if req.LADNIndication != nil {
		if ladnBytes, err := hex.DecodeString(*req.LADNIndication); err == nil {
			rr.LADNIndication = nasType.NewLADNIndication(nasMessage.RegistrationRequestLADNIndicationType)
			rr.LADNIndication.SetLen(uint16(len(ladnBytes)))
			copy(rr.LADNIndication.Buffer, ladnBytes)
		}
	}

	if req.PayloadContainer != nil {
		if pcBytes, err := hex.DecodeString(*req.PayloadContainer); err == nil {
			rr.PayloadContainer = nasType.NewPayloadContainer(nasMessage.RegistrationRequestPayloadContainerType)
			rr.PayloadContainer.SetLen(uint16(len(pcBytes)))
			copy(rr.PayloadContainer.Buffer, pcBytes)
		}
	}

	if req.NetworkSlicingIndication != nil {
		rr.NetworkSlicingIndication = nasType.NewNetworkSlicingIndication(nasMessage.RegistrationRequestNetworkSlicingIndicationType)
		rr.SetNSSCI(*req.NetworkSlicingIndication & 0x01)
		rr.SetDCNI((*req.NetworkSlicingIndication >> 1) & 0x01)
	}

	if req.UpdateType5GS != nil {
		if utBytes, err := hex.DecodeString(*req.UpdateType5GS); err == nil && len(utBytes) > 0 {
			rr.UpdateType5GS = nasType.NewUpdateType5GS(nasMessage.RegistrationRequestUpdateType5GSType)
			rr.UpdateType5GS.SetLen(uint8(len(utBytes)))
			rr.SetSMSRequested(utBytes[0] & 0x01)
			rr.SetNGRanRcu((utBytes[0] >> 1) & 0x01)
		}
	}

	if req.NASMessageContainer != nil {
		if nmcBytes, err := hex.DecodeString(*req.NASMessageContainer); err == nil {
			rr.NASMessageContainer = nasType.NewNASMessageContainer(nasMessage.RegistrationRequestNASMessageContainerType)
			rr.NASMessageContainer.SetLen(uint16(len(nmcBytes)))
			rr.NASMessageContainer.Buffer = nmcBytes
		}
	}

	if req.EPSBearerContextStatus != nil {
		if ebcBytes, err := hex.DecodeString(*req.EPSBearerContextStatus); err == nil && len(ebcBytes) >= 2 {
			rr.EPSBearerContextStatus = nasType.NewEPSBearerContextStatus(nasMessage.RegistrationRequestEPSBearerContextStatusType)
			rr.EPSBearerContextStatus.SetLen(2)
			rr.EPSBearerContextStatus.Octet[0] = ebcBytes[0]
			rr.EPSBearerContextStatus.Octet[1] = ebcBytes[1]
		}
	}
}

// maxAuthenticationResponseParameterLen is the IE's maximum, TS 24.501 §9.11.3.17.
const maxAuthenticationResponseParameterLen = 16

// BuildAuthenticationResponse builds an AUTHENTICATION RESPONSE (TS 24.501 §8.2.2).
func BuildAuthenticationResponse(resStar []byte) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeAuthenticationResponse)

	authResp := nasMessage.NewAuthenticationResponse(0)
	authResp.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	authResp.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	authResp.SetSpareHalfOctet(0)
	authResp.SetMessageType(nas.MsgTypeAuthenticationResponse)

	if len(resStar) > 0 {
		authResp.AuthenticationResponseParameter = nasType.NewAuthenticationResponseParameter(nasMessage.AuthenticationResponseAuthenticationResponseParameterType)
		n := min(len(resStar), maxAuthenticationResponseParameterLen)
		authResp.AuthenticationResponseParameter.SetLen(uint8(n))
		copy(authResp.AuthenticationResponseParameter.Octet[:], resStar[:n])
	}

	m.AuthenticationResponse = authResp

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode AuthenticationResponse: %w", err)
	}

	return data.Bytes(), nil
}

// BuildSecurityModeComplete builds a SECURITY MODE COMPLETE (TS 24.501 §8.2.26).
func BuildSecurityModeComplete(regRequestPdu []byte, imeisv string) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeSecurityModeComplete)

	smc := nasMessage.NewSecurityModeComplete(0)
	smc.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	smc.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	smc.SetSpareHalfOctet(0)
	smc.SetMessageType(nas.MsgTypeSecurityModeComplete)

	if imeisv != "" && len(imeisv) == 16 {
		pei, err := buildIMEISV(imeisv)
		if err == nil {
			smc.IMEISV = pei
		}
	}

	if regRequestPdu != nil {
		smc.NASMessageContainer = nasType.NewNASMessageContainer(nasMessage.SecurityModeCompleteNASMessageContainerType)
		smc.NASMessageContainer.SetLen(uint16(len(regRequestPdu)))
		smc.Buffer = regRequestPdu
	}

	m.SecurityModeComplete = smc

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode SecurityModeComplete: %w", err)
	}

	return data.Bytes(), nil
}

// BuildAuthenticationFailure builds an AUTHENTICATION FAILURE (TS 24.501 §8.2.4).
func BuildAuthenticationFailure(cause uint8, auts []byte) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeAuthenticationFailure)

	af := nasMessage.NewAuthenticationFailure(0)
	af.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	af.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	af.SetSpareHalfOctet(0)
	af.SetMessageType(nas.MsgTypeAuthenticationFailure)
	af.SetCauseValue(cause)

	if len(auts) > 0 {
		afp := nasType.NewAuthenticationFailureParameter(nasMessage.AuthenticationFailureAuthenticationFailureParameterType)
		afp.SetLen(uint8(len(auts)))
		copy(afp.Octet[:], auts)
		af.AuthenticationFailureParameter = afp
	}

	m.AuthenticationFailure = af

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode AuthenticationFailure: %w", err)
	}

	return data.Bytes(), nil
}

// BuildSecurityModeReject builds a SECURITY MODE REJECT (TS 24.501 §8.2.27).
func BuildSecurityModeReject(cause uint8) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeSecurityModeReject)

	smr := nasMessage.NewSecurityModeReject(0)
	smr.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	smr.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	smr.SetSpareHalfOctet(0)
	smr.SetMessageType(nas.MsgTypeSecurityModeReject)
	smr.SetCauseValue(cause)

	m.SecurityModeReject = smr

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode SecurityModeReject: %w", err)
	}

	return data.Bytes(), nil
}

// BuildIdentityResponse builds an IDENTITY RESPONSE (TS 24.501 §8.2.22).
func BuildIdentityResponse(mobileIdentity []byte) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeIdentityResponse)

	resp := nasMessage.NewIdentityResponse(0)
	resp.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	resp.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	resp.SetSpareHalfOctet(0)
	resp.SetMessageType(nas.MsgTypeIdentityResponse)

	resp.SetLen(uint16(len(mobileIdentity)))
	copy(resp.Buffer, mobileIdentity)

	m.IdentityResponse = resp

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode IdentityResponse: %w", err)
	}

	return data.Bytes(), nil
}

// BuildRegistrationComplete builds a REGISTRATION COMPLETE (TS 24.501 §8.2.8).
func BuildRegistrationComplete() ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationComplete)

	regComplete := nasMessage.NewRegistrationComplete(0)
	regComplete.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	regComplete.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	regComplete.SetSpareHalfOctet(0)
	regComplete.SetMessageType(nas.MsgTypeRegistrationComplete)

	m.RegistrationComplete = regComplete

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode RegistrationComplete: %w", err)
	}

	return data.Bytes(), nil
}

func buildIMEISV(imeisv string) (*nasType.IMEISV, error) {
	if len(imeisv) != 16 {
		return nil, fmt.Errorf("nas: IMEISV must be 16 digits")
	}

	var d [16]uint8
	for i := range 16 {
		if imeisv[i] < '0' || imeisv[i] > '9' {
			return nil, fmt.Errorf("nas: IMEISV contains non-digit characters")
		}

		d[i] = imeisv[i] - '0'
	}

	pei := nasType.NewIMEISV(nasMessage.SecurityModeCompleteIMEISVType)
	pei.SetLen(9)

	pei.SetIdentityDigit1(d[0])
	pei.SetOddEvenIdic(0)
	pei.SetTypeOfIdentity(nasMessage.MobileIdentity5GSTypeImeisv)

	pei.SetIdentityDigitP(d[1])
	pei.SetIdentityDigitP_1(d[2])
	pei.SetIdentityDigitP_2(d[3])
	pei.SetIdentityDigitP_3(d[4])
	pei.SetIdentityDigitP_4(d[5])
	pei.SetIdentityDigitP_5(d[6])
	pei.SetIdentityDigitP_6(d[7])
	pei.SetIdentityDigitP_7(d[8])
	pei.SetIdentityDigitP_8(d[9])
	pei.SetIdentityDigitP_9(d[10])
	pei.SetIdentityDigitP_10(d[11])
	pei.SetIdentityDigitP_11(d[12])
	pei.SetIdentityDigitP_12(d[13])
	pei.SetIdentityDigitP_13(d[14])
	pei.SetIdentityDigitP_14(d[15])
	pei.SetIdentityDigitP_15(0xF)

	return pei, nil
}

type ServiceRequestOpts struct {
	ServiceType uint8
	NgKsi       uint8
	Guti        *nasType.GUTI5G

	// PDUSessionStatus sets the PDU Session Status IE, bit i = session i active.
	PDUSessionStatus *[16]bool
}

// BuildServiceRequest builds a plain SERVICE REQUEST (TS 24.501 §8.2.16); a nil Guti zeroes the 5G-S-TMSI so an unknown UE can still emit one.
func BuildServiceRequest(opts *ServiceRequestOpts) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeServiceRequest)

	sr := nasMessage.NewServiceRequest(0)
	sr.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	sr.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	sr.SetMessageType(nas.MsgTypeServiceRequest)
	sr.SetServiceTypeValue(opts.ServiceType)
	sr.SetNasKeySetIdentifiler(opts.NgKsi)

	sr.SetTypeOfIdentity(nasMessage.MobileIdentity5GSType5gSTmsi)
	if opts.Guti != nil {
		sr.SetAMFSetID(opts.Guti.GetAMFSetID())
		sr.SetAMFPointer(opts.Guti.GetAMFPointer())
		sr.SetTMSI5G(opts.Guti.GetTMSI5G())
	}
	sr.TMSI5GS.SetLen(7)

	if opts.PDUSessionStatus != nil {
		flags := pduSessionBitmap(opts.PDUSessionStatus)

		sr.PDUSessionStatus = nasType.NewPDUSessionStatus(nasMessage.ServiceRequestPDUSessionStatusType)
		sr.PDUSessionStatus.SetLen(2)
		sr.PDUSessionStatus.Buffer = make([]byte, 2)
		binary.LittleEndian.PutUint16(sr.PDUSessionStatus.Buffer, flags)

		if opts.ServiceType == nasMessage.ServiceTypeData {
			sr.UplinkDataStatus = nasType.NewUplinkDataStatus(nasMessage.ServiceRequestUplinkDataStatusType)
			sr.UplinkDataStatus.SetLen(2)
			sr.UplinkDataStatus.Buffer = make([]byte, 2)
			binary.LittleEndian.PutUint16(sr.UplinkDataStatus.Buffer, flags)
		}
	}

	m.ServiceRequest = sr

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode ServiceRequest: %w", err)
	}

	return data.Bytes(), nil
}

func pduSessionBitmap(status *[16]bool) uint16 {
	var flags uint16
	for i, active := range status {
		if active {
			flags |= 1 << uint(i)
		}
	}

	return flags
}

type DeregistrationRequestOpts struct {
	Guti      *nasType.GUTI5G
	Suci      *nasType.MobileIdentity5GS
	NgKsi     uint8
	SwitchOff uint8
}

// BuildDeregistrationRequest builds a UE-originating DEREGISTRATION REQUEST (TS 24.501 §8.2.12).
func BuildDeregistrationRequest(opts *DeregistrationRequestOpts) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)

	dereg := nasMessage.NewDeregistrationRequestUEOriginatingDeregistration(0)
	dereg.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	dereg.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	dereg.SetSpareHalfOctet(0x00)
	dereg.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)
	dereg.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
	dereg.SetNasKeySetIdentifiler(opts.NgKsi)

	dereg.SetSwitchOff(opts.SwitchOff)
	dereg.SetReRegistrationRequired(0)
	dereg.SetAccessType(1)

	if opts.Guti != nil {
		dereg.MobileIdentity5GS = nasType.MobileIdentity5GS{
			Iei:    opts.Guti.Iei,
			Len:    opts.Guti.Len,
			Buffer: opts.Guti.Octet[:],
		}
	} else if opts.Suci != nil {
		dereg.MobileIdentity5GS = *opts.Suci
	} else {
		return nil, fmt.Errorf("nas: either Guti or Suci must be provided")
	}

	m.DeregistrationRequestUEOriginatingDeregistration = dereg

	data := new(bytes.Buffer)
	if err := m.GmmMessageEncode(data); err != nil {
		return nil, fmt.Errorf("nas: GMM encode DeregistrationRequest: %w", err)
	}

	return data.Bytes(), nil
}
