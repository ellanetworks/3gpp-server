// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
)

var supiRegexp = regexp.MustCompile(`(?:imsi|supi)-([0-9]{5,15})`)

type AKAResult struct {
	RESstar []byte
	Kamf    []byte
}

func ComputeResStar(k, opc, sqn, supi, snn string, rand, autn []byte) (*AKAResult, error) {
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

	groups := supiRegexp.FindStringSubmatch(supi)
	if len(groups) < 2 {
		return nil, fmt.Errorf("invalid SUPI format: %s", supi)
	}

	imsi := []byte(groups[1])

	sqnXorAK := autn[:6]

	key := make([]byte, 0, len(CK)+len(IK))
	key = append(key, CK...)
	key = append(key, IK...)

	kamf, err := derivateKamf(key, snn, imsi, sqnXorAK)
	if err != nil {
		return nil, fmt.Errorf("derive Kamf: %w", err)
	}

	resStar, err := computeResStar(key, snn, rand, RES)
	if err != nil {
		return nil, fmt.Errorf("derive RES*: %w", err)
	}

	return &AKAResult{
		RESstar: resStar,
		Kamf:    kamf,
	}, nil
}

func computeResStar(key []byte, snName string, rand, res []byte) ([]byte, error) {
	FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
	kdfVal, err := ueauth.GetKDFValue(key, FC,
		[]byte(snName), ueauth.KDFLen([]byte(snName)),
		rand, ueauth.KDFLen(rand),
		res, ueauth.KDFLen(res))
	if err != nil {
		return nil, err
	}

	return kdfVal[len(kdfVal)/2:], nil
}

func derivateKamf(key []byte, snName string, imsi, sqnXorAK []byte) ([]byte, error) {
	Kausf, err := ueauth.GetKDFValue(key, ueauth.FC_FOR_KAUSF_DERIVATION,
		[]byte(snName), ueauth.KDFLen([]byte(snName)),
		sqnXorAK, ueauth.KDFLen(sqnXorAK))
	if err != nil {
		return nil, fmt.Errorf("derive Kausf: %w", err)
	}

	Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION,
		[]byte(snName), ueauth.KDFLen([]byte(snName)))
	if err != nil {
		return nil, fmt.Errorf("derive Kseaf: %w", err)
	}

	abba := []byte{0x00, 0x00} // non-interworking 5GS (TS 33.501 §A.7.1)

	Kamf, err := ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION,
		imsi, ueauth.KDFLen(imsi),
		abba, ueauth.KDFLen(abba))
	if err != nil {
		return nil, fmt.Errorf("derive Kamf: %w", err)
	}

	return Kamf, nil
}
