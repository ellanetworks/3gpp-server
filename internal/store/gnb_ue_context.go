// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"encoding/hex"
	"fmt"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

type PDUSessionInfo struct {
	PDUSessionID uint8
	N3GNBIP      string
	DLTeid       uint32
	QFI          uint8

	ULTeid uint32
	UPFIP  string
	UEIP   string
}

type UEContext struct {
	ID string

	Supi             string
	Msin             string
	MCC              string
	MNC              string
	RoutingIndicator string

	K   string
	OPc string
	Amf string
	Sqn string

	ProtectionScheme string
	PublicKeyID      string
	PublicKeyHex     string

	Suci       nasType.MobileIdentity5GS
	SuciString string

	RANUENGAPID int64
	AMFUENGAPID int64

	UeSecurityCapability *nasType.UESecurityCapability
	CipheringAlg         uint8
	IntegrityAlg         uint8
	KnasEnc              [16]uint8
	KnasInt              [16]uint8
	Kamf                 []byte
	NgKsi                uint8
	ULCount              uint32
	DLCount              uint32
	SecurityActive       bool

	LastUplinkNAS []byte

	RAND []byte
	AUTN []byte

	DNN            string
	PDUSessionID   uint8
	PDUSessionType uint8
	SST            int32
	SD             string

	PDUSessions map[uint8]*PDUSessionInfo

	Guti *nasType.GUTI5G

	IMEISV string
}

type CreateUEOpts struct {
	Supi             string
	K                string
	OPc              string
	Amf              string
	Sqn              string
	SST              int32
	SD               string
	DNN              string
	RoutingIndicator string
	ProtectionScheme string
	PublicKeyID      string
	PublicKeyHex     string
	PDUSessionID     uint8
	PDUSessionType   uint8
	IMEISV           string
	// UESecurityCapability is hex; empty uses the default.
	UESecurityCapability string
}

func NewUEContext(id string, ranUeNgapID int64, mncLength int, opts *CreateUEOpts) (*UEContext, error) {
	supi := opts.Supi
	mcc, mnc, msin, err := crypto.ParseSUPI(supi, mncLength)
	if err != nil {
		return nil, err
	}

	protScheme := opts.ProtectionScheme
	if protScheme == "" {
		protScheme = "0"
	}
	pubKeyID := opts.PublicKeyID
	if pubKeyID == "" {
		pubKeyID = "0"
	}

	routingInd := opts.RoutingIndicator
	if routingInd == "" {
		routingInd = "0"
	}

	amf := opts.Amf
	if amf == "" {
		amf = "8000"
	}

	sqn := opts.Sqn
	if sqn == "" {
		sqn = "000000000000"
	}

	hnPubKey := crypto.HomeNetworkPublicKey{
		ProtectionScheme: protScheme,
		PublicKeyID:      pubKeyID,
	}

	if protScheme != "0" && opts.PublicKeyHex != "" {
		pubKeyBytes, err := hex.DecodeString(opts.PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid public_key_hex: %v", err)
		}

		switch protScheme {
		case "1":
			ecdhPub, err := crypto.ParseX25519PublicKey(pubKeyBytes)
			if err != nil {
				return nil, fmt.Errorf("invalid X25519 public key: %v", err)
			}
			hnPubKey.PublicKey = ecdhPub
		case "2":
			ecdhPub, err := crypto.ParseP256PublicKey(pubKeyBytes)
			if err != nil {
				return nil, fmt.Errorf("invalid P-256 public key: %v", err)
			}
			hnPubKey.PublicKey = ecdhPub
		}
	}

	suciBuffer, err := crypto.EncodeSuci(msin, mcc, mnc, routingInd, hnPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SUCI: %v", err)
	}

	suci := nasType.MobileIdentity5GS{
		Buffer: suciBuffer,
		Len:    uint16(len(suciBuffer)),
	}

	suciStr := crypto.BuildSuciString(mcc, mnc, routingInd, protScheme, pubKeyID, suciBuffer)

	capBuf := nas.DefaultUESecurityCapability
	if opts.UESecurityCapability != "" {
		if capBuf, err = hex.DecodeString(opts.UESecurityCapability); err != nil {
			return nil, fmt.Errorf("decode ue_security_capability: %w", err)
		}
	}

	secCap := &nasType.UESecurityCapability{
		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		Len:    uint8(len(capBuf)),
		Buffer: capBuf,
	}

	ue := &UEContext{
		ID:                   id,
		Supi:                 supi,
		Msin:                 msin,
		MCC:                  mcc,
		MNC:                  mnc,
		RoutingIndicator:     routingInd,
		K:                    opts.K,
		OPc:                  opts.OPc,
		Amf:                  amf,
		Sqn:                  sqn,
		ProtectionScheme:     protScheme,
		PublicKeyID:          pubKeyID,
		PublicKeyHex:         opts.PublicKeyHex,
		Suci:                 suci,
		SuciString:           suciStr,
		RANUENGAPID:          ranUeNgapID,
		UeSecurityCapability: secCap,
		DNN:                  opts.DNN,
		PDUSessionID:         opts.PDUSessionID,
		PDUSessionType:       opts.PDUSessionType,
		SST:                  opts.SST,
		SD:                   opts.SD,
		IMEISV:               opts.IMEISV,
		PDUSessions:          make(map[uint8]*PDUSessionInfo),
	}

	return ue, nil
}

func (u *UEContext) NextUL() uint32 {
	c := u.ULCount
	u.ULCount++

	return c
}

func (u *UEContext) NextDL(sequenceNumber uint8) uint32 {
	if uint8(u.DLCount&0xff) > sequenceNumber {
		u.DLCount = (u.DLCount & 0xffffff00) + 0x100 + uint32(sequenceNumber)
	} else {
		u.DLCount = (u.DLCount & 0xffffff00) + uint32(sequenceNumber)
	}

	return u.DLCount
}
