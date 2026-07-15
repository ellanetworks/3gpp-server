// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/free5gc/util/milenage"
)

// ComputeAUTS derives the re-synchronisation token AUTS (TS 33.102 §6.3.5)
// from the UE's credentials and the RAND from the Authentication Request. It is
// returned in an Authentication Failure with EMM cause #21 (TS 24.301 §5.4.2.6 c)
// or 5GMM cause #21 (TS 24.501 §5.4.1.3.7 f), both "synch failure".
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
