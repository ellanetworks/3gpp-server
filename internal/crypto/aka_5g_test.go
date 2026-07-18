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

const (
	tsSNN     = "5G:mnc001.mcc001.3gppnetwork.org"
	tsSUPI    = "imsi-001010000000001"
	tsSUPINum = "001010000000001"
)

func TestCompute5GAKAVector(t *testing.T) {
	res, err := Compute5GAKA(tsK, tsOPc, "000000000000", tsSUPI, tsMCC, tsMNC,
		mustHex(t, tsRAND), mustHex(t, tsAUTN))
	if err != nil {
		t.Fatalf("Compute5GAKA: %v", err)
	}

	// TS 33.501 §A.4
	key := append(mustHex(t, tsCK), mustHex(t, tsIK)...)
	wantResStar := kdf(t, key, 0x6B, []byte(tsSNN), mustHex(t, tsRAND), mustHex(t, tsRES))[16:32]

	if !bytes.Equal(res.RESStar, wantResStar) {
		t.Errorf("RES* = %x, want %x", res.RESStar, wantResStar)
	}

	// TS 33.501 §A.2, §A.6, §A.7
	wantKausf := kdf(t, key, 0x6A, []byte(tsSNN), mustHex(t, tsSQNxorAK))
	wantKseaf := kdf(t, wantKausf, 0x6C, []byte(tsSNN))
	wantKamf := kdf(t, wantKseaf, 0x6D, []byte(tsSUPINum), []byte{0x00, 0x00})

	if !bytes.Equal(res.Kamf, wantKamf) {
		t.Errorf("K_AMF = %x, want %x", res.Kamf, wantKamf)
	}
}

func TestCompute5GAKAMACFailure(t *testing.T) {
	autn := mustHex(t, tsAUTN)
	autn[len(autn)-1] ^= 0xff

	if _, err := Compute5GAKA(tsK, tsOPc, "000000000000", tsSUPI, tsMCC, tsMNC, mustHex(t, tsRAND), autn); !errors.Is(err, ErrMACFailure) {
		t.Fatalf("err = %v, want ErrMACFailure", err)
	}
}

func TestCompute5GAKASQNOutOfRange(t *testing.T) {
	if _, err := Compute5GAKA(tsK, tsOPc, "ffffffffffff", tsSUPI, tsMCC, tsMNC, mustHex(t, tsRAND), mustHex(t, tsAUTN)); !errors.Is(err, ErrSQNOutOfRange) {
		t.Fatalf("err = %v, want ErrSQNOutOfRange", err)
	}
}

func TestCompute5GAKAAUTNTooShort(t *testing.T) {
	_, err := Compute5GAKA(tsK, tsOPc, "000000000000", tsSUPI, tsMCC, tsMNC, mustHex(t, tsRAND), make([]byte, 5))
	if err == nil || !strings.Contains(err.Error(), "AUTN too short") {
		t.Fatalf("err = %v, want AUTN too short", err)
	}

	if errors.Is(err, ErrMACFailure) {
		t.Fatalf("short AUTN mislabelled as MAC failure: %v", err)
	}
}

// No spec vector pins AUTS for Test Set 1, so this asserts the resynch property, not a fixed output.
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
