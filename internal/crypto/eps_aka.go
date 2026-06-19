// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
)

// EPS-AKA key-derivation constants (TS 33.401 Annex A). The FC values are hex
// strings, the form ueauth.GetKDFValue expects.
const (
	fcKasme             = "10" // KASME derivation (A.2)
	fcAlgorithmKD       = "15" // K_NASenc / K_NASint derivation (A.7)
	algTypeNASEnc uint8 = 0x01 // NAS encryption algorithm distinguisher (A.7)
	algTypeNASInt uint8 = 0x02 // NAS integrity algorithm distinguisher (A.7)
)

var (
	// ErrMACFailure is returned when the AUTN MAC does not verify (TS 24.301
	// §5.4.2.6 a, EMM cause #20).
	ErrMACFailure = errors.New("AUTN MAC failure")
	// ErrSQNOutOfRange is returned when the recovered SQN is older than the
	// stored value, signalling a synch failure (TS 24.301 §5.4.2.6 c, #21).
	ErrSQNOutOfRange = errors.New("SQN out of range")
)

// EPSAKAResult holds the outputs of a successful EPS-AKA challenge.
type EPSAKAResult struct {
	RES   []byte // 8-octet response, sent verbatim in the EPS Auth Response
	Kasme []byte // 256-bit K_ASME (TS 33.401 §6.1)
}

// ComputeEPSAKA verifies the AUTN, recovers SQN, and derives RES and K_ASME for
// an EPS-AKA challenge (TS 33.401 §6.1, Annex A.2). mcc/mnc give the serving
// network identity bound into K_ASME. It returns ErrMACFailure on a bad AUTN MAC
// and ErrSQNOutOfRange when the challenge SQN is older than the stored value.
//
// EPS-AKA uses RES directly (not the 5G RES*), and K_ASME instead of K_AMF; this
// is implemented independently of Ella Core so the derived keys validate the MME.
func ComputeEPSAKA(k, opc, sqn, mcc, mnc string, rand, autn []byte) (*EPSAKAResult, error) {
	opcBytes, err := hex.DecodeString(opc)
	if err != nil {
		return nil, fmt.Errorf("decode OPc: %w", err)
	}

	kBytes, err := hex.DecodeString(k)
	if err != nil {
		return nil, fmt.Errorf("decode K: %w", err)
	}

	sqnBytes, err := hex.DecodeString(sqn)
	if err != nil {
		return nil, fmt.Errorf("decode SQN: %w", err)
	}

	if len(autn) < 6 {
		return nil, fmt.Errorf("AUTN too short: %d octets", len(autn))
	}

	sqnHn, _, IK, CK, RES, err := milenage.GenerateKeysWithAUTN(opcBytes, kBytes, rand, autn)
	if err != nil {
		return nil, ErrMACFailure
	}

	if bytes.Compare(sqnBytes, sqnHn) > 0 {
		return nil, ErrSQNOutOfRange
	}

	snid, err := tbcdPLMN(mcc, mnc)
	if err != nil {
		return nil, err
	}

	// AUTN = (SQN⊕AK) ‖ AMF ‖ MAC, so its first 6 octets are the SQN⊕AK input
	// K_ASME binds to (TS 33.401 §A.2).
	sqnXorAK := autn[:6]

	key := make([]byte, 0, len(CK)+len(IK))
	key = append(key, CK...)
	key = append(key, IK...)

	kasme, err := ueauth.GetKDFValue(key, fcKasme,
		snid, ueauth.KDFLen(snid),
		sqnXorAK, ueauth.KDFLen(sqnXorAK))
	if err != nil {
		return nil, fmt.Errorf("derive K_ASME: %w", err)
	}

	return &EPSAKAResult{RES: RES, Kasme: kasme}, nil
}

// DeriveEPSNASKeys derives the 128-bit NAS encryption and integrity keys from
// K_ASME for the selected EEA and EIA algorithm identities (TS 33.401 §A.7). The
// lower 128 bits of each 256-bit KDF output are taken.
func DeriveEPSNASKeys(kasme []byte, encAlg, intAlg uint8) (knasEnc, knasInt [16]byte, err error) {
	enc, err := ueauth.GetKDFValue(kasme, fcAlgorithmKD,
		[]byte{algTypeNASEnc}, ueauth.KDFLen([]byte{algTypeNASEnc}),
		[]byte{encAlg}, ueauth.KDFLen([]byte{encAlg}))
	if err != nil {
		return knasEnc, knasInt, fmt.Errorf("derive K_NASenc: %w", err)
	}

	intg, err := ueauth.GetKDFValue(kasme, fcAlgorithmKD,
		[]byte{algTypeNASInt}, ueauth.KDFLen([]byte{algTypeNASInt}),
		[]byte{intAlg}, ueauth.KDFLen([]byte{intAlg}))
	if err != nil {
		return knasEnc, knasInt, fmt.Errorf("derive K_NASint: %w", err)
	}

	copy(knasEnc[:], enc[16:32])
	copy(knasInt[:], intg[16:32])

	return knasEnc, knasInt, nil
}

// tbcdPLMN encodes MCC/MNC into the 3-octet TBCD serving-network identity
// (TS 23.003 §2.6); a 2-digit MNC sets the spare nibble to 0xF.
func tbcdPLMN(mcc, mnc string) ([]byte, error) {
	if len(mcc) != 3 || (len(mnc) != 2 && len(mnc) != 3) {
		return nil, fmt.Errorf("invalid PLMN mcc=%q mnc=%q", mcc, mnc)
	}

	d := make([]int, 0, 6)

	for _, s := range []string{mcc, mnc} {
		for _, r := range s {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("non-digit in plmn %q%q", mcc, mnc)
			}

			d = append(d, int(r-'0'))
		}
	}

	if len(mnc) == 2 {
		return []byte{
			byte(d[1]<<4 | d[0]),
			byte(0xF<<4 | d[2]),
			byte(d[4]<<4 | d[3]),
		}, nil
	}

	return []byte{
		byte(d[1]<<4 | d[0]),
		byte(d[5]<<4 | d[2]),
		byte(d[4]<<4 | d[3]),
	}, nil
}
