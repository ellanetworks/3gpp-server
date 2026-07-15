// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"testing"
)

// TS 33.501 §A.8
func TestAlgorithmKeyDerivationVector(t *testing.T) {
	res, err := ComputeResStar(tsK, tsOPc, "000000000000", tsSUPI, tsSNN,
		mustHex(t, tsRAND), mustHex(t, tsAUTN))
	if err != nil {
		t.Fatalf("ComputeResStar: %v", err)
	}

	const cipherAlg, intAlg = 2, 2

	var knasEnc, knasInt [16]byte
	if err := AlgorithmKeyDerivation(cipherAlg, res.Kamf, &knasEnc, intAlg, &knasInt); err != nil {
		t.Fatalf("AlgorithmKeyDerivation: %v", err)
	}

	wantEnc := kdf(t, res.Kamf, 0x69, []byte{0x01}, []byte{cipherAlg})[16:32]
	wantInt := kdf(t, res.Kamf, 0x69, []byte{0x02}, []byte{intAlg})[16:32]

	if !bytes.Equal(knasEnc[:], wantEnc) {
		t.Errorf("K_NASenc = %x, want %x", knasEnc, wantEnc)
	}

	if !bytes.Equal(knasInt[:], wantInt) {
		t.Errorf("K_NASint = %x, want %x", knasInt, wantInt)
	}
}
