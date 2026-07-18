// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"fmt"

	"github.com/free5gc/util/ueauth"
)

func DeriveEPSNASKeys(kasme []byte, cipheringAlg, integrityAlg uint8) (knasEnc, knasInt [16]byte, err error) {
	enc, err := ueauth.GetKDFValue(kasme, fcAlgorithmKD,
		[]byte{algTypeNASEnc}, ueauth.KDFLen([]byte{algTypeNASEnc}),
		[]byte{cipheringAlg}, ueauth.KDFLen([]byte{cipheringAlg}))
	if err != nil {
		return knasEnc, knasInt, fmt.Errorf("derive K_NASenc: %w", err)
	}

	intg, err := ueauth.GetKDFValue(kasme, fcAlgorithmKD,
		[]byte{algTypeNASInt}, ueauth.KDFLen([]byte{algTypeNASInt}),
		[]byte{integrityAlg}, ueauth.KDFLen([]byte{integrityAlg}))
	if err != nil {
		return knasEnc, knasInt, fmt.Errorf("derive K_NASint: %w", err)
	}

	copy(knasEnc[:], enc[16:32])
	copy(knasInt[:], intg[16:32])

	return knasEnc, knasInt, nil
}
