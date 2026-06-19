// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"github.com/free5gc/nas/security"
	"github.com/free5gc/util/ueauth"
)

func AlgorithmKeyDerivation(cipheringAlg uint8, kamf []byte, knasEnc *[16]uint8, integrityAlg uint8, knasInt *[16]uint8) error {
	P0 := []byte{security.NNASEncAlg}
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{cipheringAlg}
	L1 := ueauth.KDFLen(P1)

	kenc, err := ueauth.GetKDFValue(kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		return err
	}

	copy(knasEnc[:], kenc[16:32])

	P0 = []byte{security.NNASIntAlg}
	L0 = ueauth.KDFLen(P0)
	P1 = []byte{integrityAlg}
	L1 = ueauth.KDFLen(P1)

	kint, err := ueauth.GetKDFValue(kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		return err
	}

	copy(knasInt[:], kint[16:32])

	return nil
}
