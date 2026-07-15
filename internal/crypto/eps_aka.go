// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
)

// The fc* values are hex strings, the form ueauth.GetKDFValue expects (TS 33.401 Annex A).
const (
	fcKasme             = "10"
	fcAlgorithmKD       = "15"
	algTypeNASEnc uint8 = 0x01
	algTypeNASInt uint8 = 0x02
)

type EPSAKAResult struct {
	RES   []byte
	Kasme []byte
}

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
