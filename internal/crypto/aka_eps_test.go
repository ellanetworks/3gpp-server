// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// Reimplemented from TS 33.220 §B.2 so the assertions stay independent of the production derivation.
func kdf(t *testing.T, key []byte, fc byte, params ...[]byte) []byte {
	t.Helper()

	s := []byte{fc}
	for _, p := range params {
		s = append(s, p...)
		s = append(s, byte(len(p)>>8), byte(len(p)))
	}

	h := hmac.New(sha256.New, key)
	h.Write(s)

	return h.Sum(nil)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}

	return b
}

// TS 35.208 Test Set 1 (Milenage); AUTN is assembled as (SQN⊕AK)‖AMF‖MAC-A.
const (
	tsK        = "465b5ce8b199b49faa5f0a2ee238a6bc"
	tsOPc      = "cd63cb71954a9f4e48a5994e37a02baf"
	tsRAND     = "23553cbe9637a89d218ae64dae47bf35"
	tsAUTN     = "55f328b43577b9b94a9ffac354dfafb3"
	tsRES      = "a54211d5e3ba50bf"
	tsCK       = "b40ba9a3c58b2a05bbf0d987b21bf8cb"
	tsIK       = "f769bcd751044604127672711c6d3441"
	tsSQNxorAK = "55f328b43577"
	tsMCC      = "001"
	tsMNC      = "01"
	tsSNID     = "00f110"
)

func TestComputeEPSAKAVector(t *testing.T) {
	res, err := ComputeEPSAKA(tsK, tsOPc, "000000000000", tsMCC, tsMNC,
		mustHex(t, tsRAND), mustHex(t, tsAUTN))
	if err != nil {
		t.Fatalf("ComputeEPSAKA: %v", err)
	}

	if got := hex.EncodeToString(res.RES); got != tsRES {
		t.Errorf("RES = %s, want %s", got, tsRES)
	}

	key := append(mustHex(t, tsCK), mustHex(t, tsIK)...)
	wantKasme := kdf(t, key, 0x10, mustHex(t, tsSNID), mustHex(t, tsSQNxorAK))

	if !bytes.Equal(res.Kasme, wantKasme) {
		t.Errorf("K_ASME = %x, want %x", res.Kasme, wantKasme)
	}
}

func TestDeriveEPSNASKeysVector(t *testing.T) {
	res, err := ComputeEPSAKA(tsK, tsOPc, "000000000000", tsMCC, tsMNC,
		mustHex(t, tsRAND), mustHex(t, tsAUTN))
	if err != nil {
		t.Fatalf("ComputeEPSAKA: %v", err)
	}

	const eea, eia = 2, 2

	knasEnc, knasInt, err := DeriveEPSNASKeys(res.Kasme, eea, eia)
	if err != nil {
		t.Fatalf("DeriveEPSNASKeys: %v", err)
	}

	wantEnc := kdf(t, res.Kasme, 0x15, []byte{0x01}, []byte{eea})[16:32]
	wantInt := kdf(t, res.Kasme, 0x15, []byte{0x02}, []byte{eia})[16:32]

	if !bytes.Equal(knasEnc[:], wantEnc) {
		t.Errorf("K_NASenc = %x, want %x", knasEnc, wantEnc)
	}

	if !bytes.Equal(knasInt[:], wantInt) {
		t.Errorf("K_NASint = %x, want %x", knasInt, wantInt)
	}
}

func TestComputeEPSAKAMACFailure(t *testing.T) {
	autn := mustHex(t, tsAUTN)
	autn[len(autn)-1] ^= 0xff

	if _, err := ComputeEPSAKA(tsK, tsOPc, "000000000000", tsMCC, tsMNC, mustHex(t, tsRAND), autn); !errors.Is(err, ErrMACFailure) {
		t.Fatalf("err = %v, want ErrMACFailure", err)
	}
}

func TestComputeEPSAKASQNOutOfRange(t *testing.T) {
	if _, err := ComputeEPSAKA(tsK, tsOPc, "ffffffffffff", tsMCC, tsMNC, mustHex(t, tsRAND), mustHex(t, tsAUTN)); !errors.Is(err, ErrSQNOutOfRange) {
		t.Fatalf("err = %v, want ErrSQNOutOfRange", err)
	}
}
