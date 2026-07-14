// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

type UEContext struct {
	ID string `json:"id"`

	// Identity
	Supi             string `json:"supi"`
	Msin             string `json:"msin"`
	MCC              string `json:"mcc"`
	MNC              string `json:"mnc"`
	RoutingIndicator string `json:"routing_indicator"`

	// Credentials
	K   string `json:"k"`
	OPc string `json:"opc"`
	Amf string `json:"amf"`
	Sqn string `json:"sqn"`

	// SUCI
	ProtectionScheme string `json:"protection_scheme"`
	PublicKeyID      string `json:"public_key_id"`
	PublicKeyHex     string `json:"public_key_hex,omitempty"`

	Suci       nasType.MobileIdentity5GS `json:"-"`
	SuciString string                    `json:"suci"`

	// NGAP IDs
	RanUeNgapID int64 `json:"ran_ue_ngap_id"`
	AmfUeNgapID int64 `json:"amf_ue_ngap_id"`

	// Security
	UeSecurityCapability     *nasType.UESecurityCapability `json:"-"`
	IntegrityAlg             uint8                         `json:"-"`
	CipheringAlg             uint8                         `json:"-"`
	KnasEnc                  [16]uint8                     `json:"-"`
	KnasInt                  [16]uint8                     `json:"-"`
	Kamf                     []byte                        `json:"-"`
	NgKsi                    uint8                         `json:"-"`
	ULCount                  uint32                        `json:"-"`
	DLCount                  uint32                        `json:"-"`
	SecurityContextAvailable bool                          `json:"-"`

	// LastUplinkNAS is the most recent secured uplink NAS PDU sent, kept so it
	// can be replayed to test the AMF's NAS replay protection (TS 24.501 §4.4.3.2).
	LastUplinkNAS []byte `json:"-"`

	// Last received AuthenticationRequest parameters
	LastRAND []byte `json:"-"`
	LastAUTN []byte `json:"-"`

	// Serving network name
	Snn string `json:"snn"`

	// Session config
	DNN            string `json:"dnn"`
	PDUSessionID   uint8  `json:"pdu_session_id"`
	PDUSessionType uint8  `json:"pdu_session_type"`
	SST            int32  `json:"sst"`
	SD             string `json:"sd,omitempty"`

	// GUTI (set by AMF during registration)
	Guti *nasType.GUTI5G `json:"-"`

	// IMEISV
	IMEISV string `json:"imeisv,omitempty"`
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
}

func NewUEContext(id string, ranUeNgapID int64, mncLength int, opts *CreateUEOpts) (*UEContext, error) {
	supi := opts.Supi
	mcc, mnc, msin, err := parseSUPI(supi, mncLength)
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
			ecdhPub, err := parseX25519PublicKey(pubKeyBytes)
			if err != nil {
				return nil, fmt.Errorf("invalid X25519 public key: %v", err)
			}
			hnPubKey.PublicKey = ecdhPub
		case "2":
			ecdhPub, err := parseP256PublicKey(pubKeyBytes)
			if err != nil {
				return nil, fmt.Errorf("invalid P-256 public key: %v", err)
			}
			hnPubKey.PublicKey = ecdhPub
		}
	}

	suci, err := encodeSuci(msin, mcc, mnc, routingInd, hnPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SUCI: %v", err)
	}

	suciStr := buildSuciString(mcc, mnc, routingInd, protScheme, pubKeyID, suci)

	snn := deriveSNN(mcc, mnc)

	secCap := &nasType.UESecurityCapability{
		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		Len:    2,
		Buffer: []uint8{0xe0, 0xe0},
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
		RanUeNgapID:          ranUeNgapID,
		UeSecurityCapability: secCap,
		Snn:                  snn,
		DNN:                  opts.DNN,
		PDUSessionID:         opts.PDUSessionID,
		PDUSessionType:       opts.PDUSessionType,
		SST:                  opts.SST,
		SD:                   opts.SD,
		IMEISV:               opts.IMEISV,
	}

	return ue, nil
}

func parseSUPI(supi string, mncLength int) (mcc, mnc, msin string, err error) {
	const prefix = "imsi-"
	if len(supi) < len(prefix)+10 {
		return "", "", "", fmt.Errorf("SUPI too short: %s", supi)
	}
	if supi[:len(prefix)] != prefix {
		return "", "", "", fmt.Errorf("SUPI must start with 'imsi-': %s", supi)
	}
	digits := supi[len(prefix):]
	if len(digits) < 15 {
		return "", "", "", fmt.Errorf("IMSI must be at least 15 digits: %s", supi)
	}
	if mncLength < 2 || mncLength > 3 {
		mncLength = 2
	}
	mcc = digits[:3]
	mnc = digits[3 : 3+mncLength]
	msin = digits[3+mncLength:]

	return mcc, mnc, msin, nil
}

func encodeSuci(msin, mcc, mnc, routingIndicator string, hnPubKey crypto.HomeNetworkPublicKey) (nasType.MobileIdentity5GS, error) {
	protScheme, err := strconv.ParseUint(hnPubKey.ProtectionScheme, 10, 8)
	if err != nil {
		return nasType.MobileIdentity5GS{}, fmt.Errorf("invalid protection scheme: %v", err)
	}

	hnPubKeyId, err := strconv.ParseUint(hnPubKey.PublicKeyID, 10, 8)
	if err != nil {
		return nasType.MobileIdentity5GS{}, fmt.Errorf("invalid public key ID: %v", err)
	}

	var schemeOutput []byte
	if protScheme == 0 {
		schemeOutput, err = hex.DecodeString(crypto.Tbcd(msin))
		if err != nil {
			return nasType.MobileIdentity5GS{}, fmt.Errorf("TBCD encoding error: %v", err)
		}
	} else {
		suci, err := crypto.CipherSuci(msin, mcc, mnc, routingIndicator, hnPubKey)
		if err != nil {
			return nasType.MobileIdentity5GS{}, fmt.Errorf("SUCI cipher error: %v", err)
		}
		schemeOutput, err = hex.DecodeString(suci.SchemeOutput)
		if err != nil {
			return nasType.MobileIdentity5GS{}, fmt.Errorf("scheme output decode error: %v", err)
		}
	}

	buffer := make([]byte, 8+len(schemeOutput))
	buffer[0] = 1 // SUCI type

	plmnID, err := getMccAndMncInOctets(mcc, mnc)
	if err != nil {
		return nasType.MobileIdentity5GS{}, err
	}
	copy(buffer[1:], plmnID)

	routingInd, err := getRoutingIndicatorInOctets(routingIndicator)
	if err != nil {
		return nasType.MobileIdentity5GS{}, err
	}
	copy(buffer[4:], routingInd)

	buffer[6] = byte(protScheme)
	buffer[7] = byte(hnPubKeyId)
	copy(buffer[8:], schemeOutput)

	return nasType.MobileIdentity5GS{
		Buffer: buffer,
		Len:    uint16(len(buffer)),
	}, nil
}

func getMccAndMncInOctets(mccStr, mncStr string) ([]byte, error) {
	mcc := reverseStr(mccStr)
	mnc := reverseStr(mncStr)

	var res string
	if len(mnc) == 2 {
		res = fmt.Sprintf("%c%cf%c%c%c", mcc[1], mcc[2], mcc[0], mnc[0], mnc[1])
	} else {
		res = fmt.Sprintf("%c%c%c%c%c%c", mcc[1], mcc[2], mnc[0], mcc[0], mnc[1], mnc[2])
	}

	return hex.DecodeString(res)
}

func getRoutingIndicatorInOctets(routingIndicator string) ([]byte, error) {
	if len(routingIndicator) == 0 {
		routingIndicator = "0"
	}
	if len(routingIndicator) > 4 {
		return nil, fmt.Errorf("routing indicator must be 4 digits maximum: %s", routingIndicator)
	}

	ri := []byte(routingIndicator)
	for len(ri) < 4 {
		ri = append(ri, 'F')
	}

	for i := 1; i < len(ri); i += 2 {
		ri[i-1], ri[i] = ri[i], ri[i-1]
	}

	return hex.DecodeString(string(ri))
}

func reverseStr(s string) string {
	var aux string
	for _, v := range s {
		aux = string(v) + aux
	}
	return aux
}

func deriveSNN(mcc, mnc string) string {
	if len(mnc) == 2 {
		return "5G:mnc0" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
	}
	return "5G:mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
}

func buildSuciString(mcc, mnc, routingIndicator, protScheme, pubKeyID string, suci nasType.MobileIdentity5GS) string {
	schemeOutput := hex.EncodeToString(suci.Buffer[8:])
	return fmt.Sprintf("suci-0-%s-%s-%s-%s-%s-%s", mcc, mnc, routingIndicator, protScheme, pubKeyID, schemeOutput)
}

func parseX25519PublicKey(raw []byte) (*crypto.ECDHPublicKey, error) {
	return crypto.ParseX25519PublicKey(raw)
}

func parseP256PublicKey(raw []byte) (*crypto.ECDHPublicKey, error) {
	return crypto.ParseP256PublicKey(raw)
}
