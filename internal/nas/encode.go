// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"bytes"
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

// BuildRegistrationRequest builds a plain REGISTRATION REQUEST (TS 24.501
// §8.2.6). The mobile identity is the GUTI when the UE holds one, else its SUCI
// (§5.5.1.2.2).
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

// BuildAuthenticationResponse builds an AUTHENTICATION RESPONSE (TS 24.501
// §8.2.2) carrying RES* in the Authentication response parameter IE, which is
// at most 16 octets (§9.11.3.17).
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
		n := len(resStar)
		if n > 16 {
			n = 16
		}
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
// The NAS message container replays the initial Registration Request the UE sent
// unprotected (§4.4.6); the IMEISV answers a Security Mode Command that requested
// it (§5.4.2.3).
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

// BuildAuthenticationFailure builds an AUTHENTICATION FAILURE with the given
// 5GMM cause (TS 24.501 §8.2.4). For cause #21 "synch failure" the caller
// supplies the AUTS re-synchronisation token in the Authentication failure
// parameter IE.
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

// BuildSecurityModeReject builds a SECURITY MODE REJECT with the given 5GMM
// cause (TS 24.501 §8.2.27).
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

// BuildIdentityResponse builds an IDENTITY RESPONSE carrying the given mobile
// identity contents (TS 24.501 §8.2.22), which must match the identity type the
// AMF requested (e.g. the UE's SUCI).
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

// BuildRegistrationComplete builds a REGISTRATION COMPLETE (TS 24.501 §8.2.8)
// acknowledging a Registration Accept.
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
