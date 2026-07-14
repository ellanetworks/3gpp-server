// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"encoding/hex"
	"fmt"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapType"
)

func GetTacInBytes(tacStr string) ([]byte, error) {
	resu, err := hex.DecodeString(tacStr)
	if err != nil {
		return nil, fmt.Errorf("could not decode tac to bytes: %v", err)
	}
	return resu, nil
}

func GetSliceInBytes(sst int32, sd string) ([]byte, []byte, error) {
	sstBytes := []byte{byte(sst)}
	if sd != "" {
		sdBytes, err := hex.DecodeString(sd)
		if err != nil {
			return sstBytes, nil, fmt.Errorf("could not decode sd to bytes: %v", err)
		}
		return sstBytes, sdBytes, nil
	}
	return sstBytes, nil, nil
}

// encodePLMN encodes an MCC/MNC pair into the 3-octet BCD PLMN identity
// (TS 23.003 §2.2 / TS 24.008 §10.5.1.3): octet 1 = MCC2|MCC1, octet 2 =
// MNC3|MCC3, octet 3 = MNC2|MNC1, with a 2-digit MNC taking the 0xF filler in
// its third digit. It validates lengths and digits so malformed input yields an
// error, not a panic or a silently-empty mandatory IE.
func encodePLMN(mcc, mnc string) ([]byte, error) {
	if len(mcc) != 3 {
		return nil, fmt.Errorf("mcc must be 3 digits, got %q", mcc)
	}

	if len(mnc) != 2 && len(mnc) != 3 {
		return nil, fmt.Errorf("mnc must be 2 or 3 digits, got %q", mnc)
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

	p := make([]byte, 3)
	p[0] = byte(d[1]<<4 | d[0])

	if len(mnc) == 2 {
		p[1] = byte(0xF<<4 | d[2])
	} else {
		p[1] = byte(d[5]<<4 | d[2])
	}

	p[2] = byte(d[4]<<4 | d[3])

	return p, nil
}

func GetNRCellIdentity(gnbID string) (ngapType.NRCellIdentity, error) {
	nci, err := hex.DecodeString(gnbID)
	if err != nil {
		return ngapType.NRCellIdentity{}, fmt.Errorf("could not get NRCellIdentity: %v", err)
	}
	padding := make([]byte, 2)
	return ngapType.NRCellIdentity{
		Value: aper.BitString{
			Bytes:     append(nci, padding...),
			BitLength: 36,
		},
	}, nil
}
