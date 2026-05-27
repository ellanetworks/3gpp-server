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
			return nil, fmt.Errorf("decode mobile_identity_override: %w", err)
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
			return nil, fmt.Errorf("decode ue_security_capability: %w", err)
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
		return nil, fmt.Errorf("GMM encode error: %w", err)
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
