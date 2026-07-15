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

// Protect wraps a plain NAS message in the EPS security wrapper (TS 24.301 §9.1.1).
func Protect(plain []byte, sht SecurityHeaderType, count uint32, eia, eea uint8, knasInt, knasEnc [16]byte) ([]byte, error) {
	integ, err := integrityFor(eia)
	if err != nil {
		return nil, err
	}

	ciph, err := cipherFor(eea)
	if err != nil {
		return nil, err
	}

	return eps.Protect(plain, sht, count, DirectionUplink, knasInt, knasEnc, integ, ciph)
}

// Unprotect verifies the NAS-MAC of a downlink message and returns the recovered plain message (TS 24.301 §9.1.1).
func Unprotect(b []byte, count uint32, eia, eea uint8, knasInt, knasEnc [16]byte) ([]byte, error) {
	integ, err := integrityFor(eia)
	if err != nil {
		return nil, err
	}

	ciph, err := cipherFor(eea)
	if err != nil {
		return nil, err
	}

	return eps.Unprotect(b, count, DirectionDownlink, knasInt, knasEnc, integ, ciph)
}
