// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/free5gc/util/milenage"
)

func ComputeAUTS(k, opc, sqn string, rand []byte) ([]byte, error) {
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

	auts, err := milenage.GenerateAUTS(opcBytes, kBytes, rand, sqnBytes)
	if err != nil {
		return nil, fmt.Errorf("generate AUTS: %w", err)
	}

	return auts, nil
}
