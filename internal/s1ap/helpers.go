// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"fmt"
	"net"

	"github.com/ellanetworks/core/s1ap"
)

// parseTransportAddr parses a TransportLayerAddress IE value (TS 36.413
// §9.2.2.1), returning the 4-byte form for IPv4 so the IE keeps its 32-bit
// width.
func parseTransportAddr(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid transport layer address %q", s)
	}

	if v4 := ip.To4(); v4 != nil {
		return v4, nil
	}

	return ip, nil
}

// encodePLMN packs an MCC/MNC pair into the 3-octet TBCD PLMN identity
// (TS 23.003 §2.6): octet 1 = MCC2|MCC1, octet 2 = MNC3|MCC3, octet 3 =
// MNC2|MNC1. A 2-digit MNC takes the 0xF filler in its third digit.
func encodePLMN(mcc, mnc string) (s1ap.PLMNIdentity, error) {
	if len(mcc) != 3 {
		return s1ap.PLMNIdentity{}, fmt.Errorf("mcc must be 3 digits, got %q", mcc)
	}

	if len(mnc) != 2 && len(mnc) != 3 {
		return s1ap.PLMNIdentity{}, fmt.Errorf("mnc must be 2 or 3 digits, got %q", mnc)
	}

	d := make([]int, 0, 6)

	for _, s := range []string{mcc, mnc} {
		for _, r := range s {
			if r < '0' || r > '9' {
				return s1ap.PLMNIdentity{}, fmt.Errorf("non-digit in plmn %q%q", mcc, mnc)
			}

			d = append(d, int(r-'0'))
		}
	}

	var p s1ap.PLMNIdentity

	if len(mnc) == 2 {
		p[0] = byte(d[1]<<4 | d[0])
		p[1] = byte(0xF<<4 | d[2])
		p[2] = byte(d[4]<<4 | d[3])
	} else {
		p[0] = byte(d[1]<<4 | d[0])
		p[1] = byte(d[5]<<4 | d[2])
		p[2] = byte(d[4]<<4 | d[3])
	}

	return p, nil
}
