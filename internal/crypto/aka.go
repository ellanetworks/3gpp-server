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

// supiRegexp matches the "imsi-<digits>" form of the SUPI (TS 29.571 §5.3.2);
// the captured digits are the IMSI that P0 of the K_AMF derivation is set to
// (TS 33.501 §A.7.0).
var supiRegexp = regexp.MustCompile(`(?:imsi|supi)-([0-9]{5,15})`)

// AKAResult holds the outputs of a successful 5G-AKA challenge.
type AKAResult struct {
	RESstar []byte // 128-bit RES*, sent in the Authentication Response (TS 33.501 §A.4)
	Kamf    []byte // 256-bit K_AMF (TS 33.501 §A.7)
}

// ComputeResStar verifies the AUTN, recovers SQN, and derives RES* and K_AMF for
// a 5G-AKA challenge (TS 33.501 §6.1.3.2, Annex A.2/A.4/A.6/A.7). snn is the
// serving network name bound into K_AUSF and K_SEAF; supi supplies the IMSI that
// K_AMF binds to. It returns ErrMACFailure on a bad AUTN MAC and ErrSQNOutOfRange
// when the challenge SQN is older than the stored value.
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

	// AUTN = (SQN⊕AK) ‖ AMF ‖ MAC, so its first 6 octets are the SQN⊕AK input
	// K_AUSF binds to (TS 33.501 §A.2).
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

	// ABBA parameter, 0x0000 for a non-interworking 5GS (TS 33.501 §A.7.1).
	P1 := []byte{0x00, 0x00}

	Kamf, err := ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION,
		imsi, ueauth.KDFLen(imsi),
		P1, ueauth.KDFLen(P1))
	if err != nil {
		return nil, fmt.Errorf("derive Kamf: %w", err)
	}

	return Kamf, nil
}
