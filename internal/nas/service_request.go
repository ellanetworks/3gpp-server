package nas

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

// ServiceRequestOpts configures a 5GMM Service Request (TS 24.501 §8.2.16).
type ServiceRequestOpts struct {
	ServiceType uint8           // nasMessage.ServiceType* (default Data)
	NgKsi       uint8           // NAS key set identifier of the current 5G security context
	Guti        *nasType.GUTI5G // source of the 5G-S-TMSI mobile identity

	// PDUSessionStatus, when non-nil, sets the PDU Session Status IE (bit i =
	// session i is active in the UE). For ServiceTypeData the same bitmap is
	// also reflected in the Uplink Data Status IE to request user-plane
	// re-activation.
	PDUSessionStatus *[16]bool
}

// BuildServiceRequest builds a plain (unprotected) Service Request NAS PDU. The
// caller wraps it with EncodeNasPduWithSecurity using an integrity-protected
// security header before transport.
func BuildServiceRequest(opts *ServiceRequestOpts) ([]byte, error) {
	if opts.Guti == nil {
		return nil, fmt.Errorf("service request requires a GUTI (UE not registered?)")
	}

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeServiceRequest)

	sr := nasMessage.NewServiceRequest(0)
	sr.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	sr.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	sr.SetMessageType(nas.MsgTypeServiceRequest)
	sr.SetServiceTypeValue(opts.ServiceType)
	sr.SetNasKeySetIdentifiler(opts.NgKsi)

	// 5G-S-TMSI mobile identity (type of identity = 4) derived from the GUTI.
	sr.SetTypeOfIdentity(nasMessage.MobileIdentity5GSType5gSTmsi)
	sr.SetAMFSetID(opts.Guti.GetAMFSetID())
	sr.SetAMFPointer(opts.Guti.GetAMFPointer())
	sr.SetTMSI5G(opts.Guti.GetTMSI5G())
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
		return nil, fmt.Errorf("GMM encode ServiceRequest: %w", err)
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
