// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"encoding/hex"
	"fmt"

	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/security"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

// EncodeOption tweaks the security wrapping of an uplink NAS message for
// negative testing.
type EncodeOption func(*encodeOptions)

type encodeOptions struct {
	corruptMAC    bool
	countOverride *uint32
}

// WithCorruptMAC flips a byte of the NAS-MAC so the AMF's integrity check fails;
// the AMF must discard the message (TS 24.501 §4.4.4.3).
func WithCorruptMAC() EncodeOption {
	return func(o *encodeOptions) { o.corruptMAC = true }
}

// WithNASCountOverride forces the uplink NAS COUNT written into the message,
// leaving the UE's real counter to advance normally.
func WithNASCountOverride(count uint32) EncodeOption {
	return func(o *encodeOptions) { o.countOverride = &count }
}

func EncodeNasPduWithSecurity(ue *store.UEContext, pdu []byte, securityHeaderType uint8, opts ...EncodeOption) ([]byte, error) {
	m := gonas.NewMessage()
	if err := m.PlainNasDecode(&pdu); err != nil {
		return nil, fmt.Errorf("nas: plain NAS decode: %w", err)
	}

	m.SecurityHeader = gonas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    securityHeaderType,
	}

	return nasEncode(ue, m, securityHeaderType, opts...)
}

func nasEncode(ue *store.UEContext, msg *gonas.Message, securityHeaderType uint8, opts ...EncodeOption) ([]byte, error) {
	var o encodeOptions
	for _, opt := range opts {
		opt(&o)
	}

	if !ue.SecurityContextAvailable && len(ue.Kamf) == 0 {
		return nil, fmt.Errorf("nas: no security context available")
	}

	if securityHeaderType == gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext ||
		securityHeaderType == gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext {
		ue.ULCount = 0
		ue.DLCount = 0
	}

	count := ue.ULCount
	if o.countOverride != nil {
		count = *o.countOverride
	}

	sequenceNumber := uint8(count & 0xff)

	payload, err := msg.PlainNasEncode()
	if err != nil {
		return nil, fmt.Errorf("nas: plain NAS encode: %w", err)
	}

	if securityHeaderType != gonas.SecurityHeaderTypeIntegrityProtected &&
		securityHeaderType != gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext {
		if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, count, security.Bearer3GPP,
			security.DirectionUplink, payload); err != nil {
			return nil, fmt.Errorf("nas: NAS encrypt: %w", err)
		}
	}

	payload = append([]byte{sequenceNumber}, payload...)

	mac32, err := security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, count, security.Bearer3GPP, security.DirectionUplink, payload)
	if err != nil {
		return nil, fmt.Errorf("nas: NAS MAC: %w", err)
	}

	payload = append(mac32, payload...)
	msgSecurityHeader := []byte{msg.ProtocolDiscriminator, msg.SecurityHeaderType}
	payload = append(msgSecurityHeader, payload...)

	// The 5GS security header is 2 octets, so the NAS-MAC's first octet is at index 2.
	if o.corruptMAC && len(payload) >= 7 {
		payload[2] ^= 0xff
	}

	ue.ULCount++
	ue.LastUplinkNAS = payload

	return payload, nil
}

func DecodeSecuredNAS(ue *store.UEContext, message []byte) (*NASResponse, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("nas: empty NAS PDU")
	}

	resp := &NASResponse{
		RawHex: hex.EncodeToString(message),
	}

	secHeaderType := gonas.GetSecurityHeaderType(message) & 0x0f
	resp.SecurityHeaderType = securityHeaderTypeToString(secHeaderType)

	if secHeaderType == gonas.SecurityHeaderTypePlainNas {
		return Decode(message)
	}

	if len(message) < 7 {
		return nil, fmt.Errorf("nas: secured NAS too short: %d bytes", len(message))
	}

	sequenceNumber := message[6]
	payload := make([]byte, len(message)-7)
	copy(payload, message[7:])

	cph := false
	newSecurityContext := false

	switch secHeaderType {
	case gonas.SecurityHeaderTypeIntegrityProtected:
	case gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered:
		cph = true
	case gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext:
		newSecurityContext = true
	case gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext:
		cph = true
		newSecurityContext = true
	}

	dlSQN := uint8(ue.DLCount & 0xff)
	if dlSQN > sequenceNumber {
		ue.DLCount = (ue.DLCount & 0xffffff00) + 0x100 + uint32(sequenceNumber)
	} else {
		ue.DLCount = (ue.DLCount & 0xffffff00) + uint32(sequenceNumber)
	}

	if cph && ue.SecurityContextAvailable {
		if err := security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.DLCount, security.Bearer3GPP,
			security.DirectionDownlink, payload); err != nil {
			return nil, fmt.Errorf("nas: NAS decrypt: %w", err)
		}
	}

	m := new(gonas.Message)
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)

	if err := m.PlainNasDecode(&payloadCopy); err != nil {
		return nil, fmt.Errorf("nas: NAS decode after decrypt: %w", err)
	}

	if newSecurityContext && m.GmmMessage != nil {
		if m.GmmHeader.GetMessageType() == gonas.MsgTypeSecurityModeCommand {
			ue.CipheringAlg = m.SelectedNASSecurityAlgorithms.GetTypeOfCipheringAlgorithm()
			ue.IntegrityAlg = m.SelectedNASSecurityAlgorithms.GetTypeOfIntegrityProtectionAlgorithm()

			if err := deriveAlgKeys(ue); err != nil {
				return nil, fmt.Errorf("nas: derive algorithm keys: %w", err)
			}

			ue.DLCount = 0
			ue.SecurityContextAvailable = true
		}
	}

	if m.GmmMessage == nil {
		messageType, err := unknownMessageType(m)
		if err != nil {
			return nil, err
		}

		resp.MessageType = messageType

		return resp, nil
	}

	if err := decodeGmm(m, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func deriveAlgKeys(ue *store.UEContext) error {
	return deriveAlgKeysFromKamf(ue.CipheringAlg, ue.Kamf, &ue.KnasEnc, ue.IntegrityAlg, &ue.KnasInt)
}

func deriveAlgKeysFromKamf(cipheringAlg uint8, kamf []byte, knasEnc *[16]uint8, integrityAlg uint8, knasInt *[16]uint8) error {
	if len(kamf) == 0 {
		return fmt.Errorf("nas: kamf is empty")
	}

	return crypto.AlgorithmKeyDerivation(cipheringAlg, kamf, knasEnc, integrityAlg, knasInt)
}
