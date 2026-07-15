// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

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
