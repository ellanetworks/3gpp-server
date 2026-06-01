package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
)

type AKAResult struct {
	RESstar []byte
	Kamf    []byte
}

func ComputeResStar(k, opc, sqn, supi, snn string, rand, autn []byte) (*AKAResult, error) {
	opcBytes, err := hex.DecodeString(opc)
	if err != nil {
		return nil, fmt.Errorf("decode OPc: %v", err)
	}

	kBytes, err := hex.DecodeString(k)
	if err != nil {
		return nil, fmt.Errorf("decode K: %v", err)
	}

	sqnBytes, err := hex.DecodeString(sqn)
	if err != nil {
		return nil, fmt.Errorf("decode SQN: %v", err)
	}

	sqnHn, AK, IK, CK, RES, err := milenage.GenerateKeysWithAUTN(opcBytes, kBytes, rand, autn)
	if err != nil {
		return nil, errors.New("milenage MAC failure")
	}

	if bytes.Compare(sqnBytes, sqnHn) > 0 {
		return nil, errors.New("sequence number out of range")
	}

	key := append(CK, IK...)

	kamf, err := derivateKamf(key, snn, supi, sqnHn, AK)
	if err != nil {
		return nil, fmt.Errorf("derive Kamf: %v", err)
	}

	resStar, err := computeResStar(key, snn, rand, RES)
	if err != nil {
		return nil, fmt.Errorf("derive RES*: %v", err)
	}

	return &AKAResult{
		RESstar: resStar,
		Kamf:    kamf,
	}, nil
}

// ComputeAUTS derives the re-synchronisation token AUTS (TS 33.102 §6.3.5)
// from the UE's credentials and the RAND from the Authentication Request. It is
// returned in an Authentication Failure with 5GMM cause #21 "synch failure".
func ComputeAUTS(k, opc, sqn string, rand []byte) ([]byte, error) {
	opcBytes, err := hex.DecodeString(opc)
	if err != nil {
		return nil, fmt.Errorf("decode OPc: %v", err)
	}

	kBytes, err := hex.DecodeString(k)
	if err != nil {
		return nil, fmt.Errorf("decode K: %v", err)
	}

	sqnBytes, err := hex.DecodeString(sqn)
	if err != nil {
		return nil, fmt.Errorf("decode SQN: %v", err)
	}

	auts, err := milenage.GenerateAUTS(opcBytes, kBytes, rand, sqnBytes)
	if err != nil {
		return nil, fmt.Errorf("generate AUTS: %v", err)
	}

	return auts, nil
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

func derivateKamf(key []byte, snName, supi string, SQN, AK []byte) ([]byte, error) {
	SQNxorAK := make([]byte, 6)
	for i := range SQN {
		SQNxorAK[i] = SQN[i] ^ AK[i]
	}

	Kausf, err := ueauth.GetKDFValue(key, ueauth.FC_FOR_KAUSF_DERIVATION,
		[]byte(snName), ueauth.KDFLen([]byte(snName)),
		SQNxorAK, ueauth.KDFLen(SQNxorAK))
	if err != nil {
		return nil, fmt.Errorf("derive Kausf: %v", err)
	}

	Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION,
		[]byte(snName), ueauth.KDFLen([]byte(snName)))
	if err != nil {
		return nil, fmt.Errorf("derive Kseaf: %v", err)
	}

	supiRegexp := regexp.MustCompile(`(?:imsi|supi)-([0-9]{5,15})`)
	groups := supiRegexp.FindStringSubmatch(supi)
	if len(groups) < 2 {
		return nil, fmt.Errorf("invalid SUPI format: %s", supi)
	}

	P0 := []byte(groups[1])
	P1 := []byte{0x00, 0x00}

	Kamf, err := ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION,
		P0, ueauth.KDFLen(P0),
		P1, ueauth.KDFLen(P1))
	if err != nil {
		return nil, fmt.Errorf("derive Kamf: %v", err)
	}

	return Kamf, nil
}
