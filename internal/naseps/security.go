// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import (
	"fmt"

	"github.com/ellanetworks/core/nas/common"
	"github.com/ellanetworks/core/nas/eps"
)

type SecurityHeaderType = eps.SecurityHeaderType

const (
	SHTPlain                         = eps.SHTPlain
	SHTIntegrityProtected            = eps.SHTIntegrityProtected
	SHTIntegrityProtectedCiphered    = eps.SHTIntegrityProtectedCiphered
	SHTIntegrityProtectedNewContext  = eps.SHTIntegrityProtectedNewContext
	SHTIntegrityProtectedCipheredNew = eps.SHTIntegrityProtectedCipheredNewContext
)

const (
	DirectionUplink   = common.DirectionUplink
	DirectionDownlink = common.DirectionDownlink
)

func integrityFor(eia uint8) (common.Integrity, error) {
	switch eia {
	case 0:
		return common.NullIntegrity{}, nil
	case 1:
		return common.SNOW3GIntegrity{}, nil
	case 2:
		return common.AESCMACIntegrity{}, nil
	default:
		return nil, fmt.Errorf("naseps: unsupported integrity algorithm EIA%d", eia)
	}
}

func cipherFor(eea uint8) (common.Cipher, error) {
	switch eea {
	case 0:
		return common.NullCipher{}, nil
	case 1:
		return common.SNOW3GCipher{}, nil
	case 2:
		return common.AESCTRCipher{}, nil
	default:
		return nil, fmt.Errorf("naseps: unsupported ciphering algorithm EEA%d", eea)
	}
}

func SecurityHeader(b []byte) (SecurityHeaderType, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("naseps: empty NAS message")
	}

	if b[0]&0x0F != eps.PDEMM {
		return 0, fmt.Errorf("naseps: not an EMM message (PD %#x)", b[0]&0x0F)
	}

	return SecurityHeaderType(b[0] >> 4), nil
}

// PeekProtectedPayload skips MAC verification: a Security Mode Command's algorithms must be read before the keys that depend on them exist.
func PeekProtectedPayload(b []byte) ([]byte, error) {
	m, err := eps.ParseSecurityProtectedMessage(b)
	if err != nil {
		return nil, err
	}

	return m.Payload, nil
}

// Protect wraps a plain NAS message in the EPS security wrapper (TS 24.301 §9.1.1).
func Protect(plain []byte, sht SecurityHeaderType, count uint32, cipheringAlg, integrityAlg uint8, knasEnc, knasInt [16]byte) ([]byte, error) {
	integ, err := integrityFor(integrityAlg)
	if err != nil {
		return nil, err
	}

	ciph, err := cipherFor(cipheringAlg)
	if err != nil {
		return nil, err
	}

	return eps.Protect(plain, sht, count, DirectionUplink, knasInt, knasEnc, integ, ciph)
}

// Unprotect verifies the NAS-MAC of a downlink message and returns the recovered plain message (TS 24.301 §9.1.1).
func Unprotect(b []byte, count uint32, cipheringAlg, integrityAlg uint8, knasEnc, knasInt [16]byte) ([]byte, error) {
	integ, err := integrityFor(integrityAlg)
	if err != nil {
		return nil, err
	}

	ciph, err := cipherFor(cipheringAlg)
	if err != nil {
		return nil, err
	}

	return eps.Unprotect(b, count, DirectionDownlink, knasInt, knasEnc, integ, ciph)
}
