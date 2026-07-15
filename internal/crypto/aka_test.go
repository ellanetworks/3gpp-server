// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/free5gc/util/milenage"
)

// Serving network name (TS 24.501 §9.11.3.32) and SUPI for the 5G-AKA vectors.
// The digits after "imsi-" are P0 in the K_AMF derivation (TS 33.501 §A.7).
const (
	tsSNN     = "5G:mnc001.mcc001.3gppnetwork.org"
	tsSUPI    = "imsi-001010000000001"
	tsSUPINum = "001010000000001"
)

// The 5G key hierarchy is anchored on Milenage Test Set 1 (TS 35.208), reusing
// tsK/tsOPc/tsRAND/tsAUTN/tsCK/tsIK/tsRES/tsSQNxorAK from eps_aka_test.go, then
// cross-checking each KDF step against the independent kdf helper (TS 33.501
// Annex A). AUTN = (SQN⊕AK)‖AMF‖MAC, so tsSQNxorAK is AUTN[:6], the K_AUSF input.
func TestComputeResStarVector(t *testing.T) {
	res, err := ComputeResStar(tsK, tsOPc, "000000000000", tsSUPI, tsSNN,
		mustHex(t, tsRAND), mustHex(t, tsAUTN))
	if err != nil {
		t.Fatalf("ComputeResStar: %v", err)
	}

	// RES* = lower half of KDF(CK‖IK, 0x6B, SNN, RAND, RES) (TS 33.501 §A.4).
	key := append(mustHex(t, tsCK), mustHex(t, tsIK)...)
	wantResStar := kdf(t, key, 0x6B, []byte(tsSNN), mustHex(t, tsRAND), mustHex(t, tsRES))[16:32]

	if !bytes.Equal(res.RESstar, wantResStar) {
		t.Errorf("RES* = %x, want %x", res.RESstar, wantResStar)
	}

	// K_AUSF = KDF(CK‖IK, 0x6A, SNN, SQN⊕AK) (TS 33.501 §A.2).
	wantKausf := kdf(t, key, 0x6A, []byte(tsSNN), mustHex(t, tsSQNxorAK))
	// K_SEAF = KDF(K_AUSF, 0x6C, SNN) (TS 33.501 §A.6).
	wantKseaf := kdf(t, wantKausf, 0x6C, []byte(tsSNN))
	// K_AMF = KDF(K_SEAF, 0x6D, SUPI, ABBA) with ABBA = 0x0000 (TS 33.501 §A.7).
	wantKamf := kdf(t, wantKseaf, 0x6D, []byte(tsSUPINum), []byte{0x00, 0x00})

	if !bytes.Equal(res.Kamf, wantKamf) {
		t.Errorf("K_AMF = %x, want %x", res.Kamf, wantKamf)
	}
}

func TestComputeResStarMACFailure(t *testing.T) {
	autn := mustHex(t, tsAUTN)
	autn[len(autn)-1] ^= 0xff // corrupt the MAC field

	if _, err := ComputeResStar(tsK, tsOPc, "000000000000", tsSUPI, tsSNN, mustHex(t, tsRAND), autn); !errors.Is(err, ErrMACFailure) {
		t.Fatalf("err = %v, want ErrMACFailure", err)
	}
}

func TestComputeResStarSQNOutOfRange(t *testing.T) {
	if _, err := ComputeResStar(tsK, tsOPc, "ffffffffffff", tsSUPI, tsSNN, mustHex(t, tsRAND), mustHex(t, tsAUTN)); !errors.Is(err, ErrSQNOutOfRange) {
		t.Fatalf("err = %v, want ErrSQNOutOfRange", err)
	}
}

// A too-short AUTN must be reported as a length error, not the Milenage MAC
// failure the library returns for it (TS 33.501 §6.1.3.2).
func TestComputeResStarAUTNTooShort(t *testing.T) {
	_, err := ComputeResStar(tsK, tsOPc, "000000000000", tsSUPI, tsSNN, mustHex(t, tsRAND), make([]byte, 5))
	if err == nil || !strings.Contains(err.Error(), "AUTN too short") {
		t.Fatalf("err = %v, want AUTN too short", err)
	}

	if errors.Is(err, ErrMACFailure) {
		t.Fatalf("short AUTN mislabelled as MAC failure: %v", err)
	}
}

// AUTS round-trip: milenage.ValidateAUTS recovers the SQN sealed by ComputeAUTS
// (TS 33.102 §6.3.3). No spec vector pins AUTS for Test Set 1, so this asserts
// the resynch property, not a fixed output.
func TestComputeAUTSRoundTrip(t *testing.T) {
	const sqn = "000000000021"

	auts, err := ComputeAUTS(tsK, tsOPc, sqn, mustHex(t, tsRAND))
	if err != nil {
		t.Fatalf("ComputeAUTS: %v", err)
	}

	sqnMs, err := milenage.ValidateAUTS(mustHex(t, tsOPc), mustHex(t, tsK), mustHex(t, tsRAND), auts)
	if err != nil {
		t.Fatalf("ValidateAUTS: %v", err)
	}

	if got := hex.EncodeToString(sqnMs); got != sqn {
		t.Errorf("recovered SQN = %s, want %s", got, sqn)
	}
}
