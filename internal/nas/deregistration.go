// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"bytes"
	"fmt"

	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

type DeregistrationRequestOpts struct {
	Guti      *nasType.GUTI5G
	Suci      *nasType.MobileIdentity5GS
	NgKsi     uint8
	SwitchOff uint8
}

// BuildDeregistrationRequest builds a UE-originating DEREGISTRATION REQUEST
// (TS 24.501 §8.2.12) over 3GPP access. With SwitchOff set the AMF sends no
// Deregistration Accept (§5.5.2.2.2).
func BuildDeregistrationRequest(opts *DeregistrationRequestOpts) ([]byte, error) {
	m := gonas.NewMessage()
	m.GmmMessage = gonas.NewGmmMessage()
	m.GmmHeader.SetMessageType(gonas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)

	dereg := nasMessage.NewDeregistrationRequestUEOriginatingDeregistration(0)
	dereg.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	dereg.SetSecurityHeaderType(gonas.SecurityHeaderTypePlainNas)
	dereg.SetSpareHalfOctet(0x00)
	dereg.SetMessageType(gonas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)
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
