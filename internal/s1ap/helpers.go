// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"fmt"
	"net"

	"github.com/ellanetworks/core/s1ap"
)

// IPv4 must return in 4-byte form to keep the IE at its 32-bit width (TS 36.414 §5.3).
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

// TBCD nibbles are swapped within each octet, and a 2-digit MNC takes an 0xF filler (TS 24.008 §10.5.1.3).
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
