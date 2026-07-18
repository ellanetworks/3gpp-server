// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

import (
	"bytes"
	"errors"
	"fmt"

	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/security"
)

var ErrMACMismatch = errors.New("nas: NAS-MAC mismatch")

// SecurityHeaderType is the 5GS security header type (TS 24.501 §9.3); free5gc
// models it as a bare uint8, so this is an alias rather than a defined type.
type SecurityHeaderType = uint8

// SecurityHeader returns the 5GS security header type of a NAS PDU (TS 24.501 §9.3).
func SecurityHeader(message []byte) (SecurityHeaderType, error) {
	if len(message) < 2 {
		return 0, fmt.Errorf("nas: NAS PDU too short: %d bytes", len(message))
	}

	return gonas.GetSecurityHeaderType(message) & 0x0f, nil
}

// PeekProtectedPayload returns the inner NAS message of a secured PDU without verifying the
// NAS-MAC, so a Security Mode Command's algorithms can be read before their keys exist.
func PeekProtectedPayload(message []byte) ([]byte, error) {
	if len(message) < 7 {
		return nil, fmt.Errorf("nas: secured NAS too short: %d bytes", len(message))
	}

	inner := make([]byte, len(message)-7)
	copy(inner, message[7:])

	return inner, nil
}

// Protect wraps a plain 5GS NAS message in the security wrapper at the given COUNT (TS 24.501 §9.1.1).
func Protect(plain []byte, sht SecurityHeaderType, count uint32, cipheringAlg, integrityAlg uint8, knasEnc, knasInt [16]byte) ([]byte, error) {
	m := gonas.NewMessage()
	if err := m.PlainNasDecode(&plain); err != nil {
		return nil, fmt.Errorf("nas: plain NAS decode: %w", err)
	}

	m.SecurityHeader = gonas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    sht,
	}

	payload, err := m.PlainNasEncode()
	if err != nil {
		return nil, fmt.Errorf("nas: plain NAS encode: %w", err)
	}

	if ciphered(sht) {
		if err = security.NASEncrypt(cipheringAlg, knasEnc, count, security.Bearer3GPP, security.DirectionUplink, payload); err != nil {
			return nil, fmt.Errorf("nas: NAS encrypt: %w", err)
		}
	}

	payload = append([]byte{uint8(count & 0xff)}, payload...)

	mac, err := security.NASMacCalculate(integrityAlg, knasInt, count, security.Bearer3GPP, security.DirectionUplink, payload)
	if err != nil {
		return nil, fmt.Errorf("nas: NAS MAC: %w", err)
	}

	payload = append(mac, payload...)

	return append([]byte{nasMessage.Epd5GSMobilityManagementMessage, sht}, payload...), nil
}

// Unprotect verifies the downlink NAS-MAC, decrypts, and returns the recovered plain 5GS NAS
// message; it returns the message with ErrMACMismatch when the MAC does not verify (TS 24.501 §9.1.1).
func Unprotect(message []byte, count uint32, cipheringAlg, integrityAlg uint8, knasEnc, knasInt [16]byte) ([]byte, error) {
	if len(message) < 7 {
		return nil, fmt.Errorf("nas: secured NAS too short: %d bytes", len(message))
	}

	receivedMAC := message[2:6]

	macInput := make([]byte, len(message)-6)
	copy(macInput, message[6:])

	mac, err := security.NASMacCalculate(integrityAlg, knasInt, count, security.Bearer3GPP, security.DirectionDownlink, macInput)
	if err != nil {
		return nil, fmt.Errorf("nas: NAS MAC: %w", err)
	}

	inner := macInput[1:]
	if ciphered(gonas.GetSecurityHeaderType(message) & 0x0f) {
		if err := security.NASEncrypt(cipheringAlg, knasEnc, count, security.Bearer3GPP, security.DirectionDownlink, inner); err != nil {
			return nil, fmt.Errorf("nas: NAS decrypt: %w", err)
		}
	}

	if !bytes.Equal(mac, receivedMAC) {
		return inner, ErrMACMismatch
	}

	return inner, nil
}

func ciphered(sht SecurityHeaderType) bool {
	return sht == gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered ||
		sht == gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext
}
