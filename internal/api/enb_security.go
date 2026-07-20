// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import "github.com/ellanetworks/3gpp-server/internal/naseps"

// epsDLSequenceNumber returns the NAS sequence number of a downlink security-protected
// EPS NAS message (TS 24.301 §9.1: 1-octet header, 4-octet MAC, then the sequence number).
func epsDLSequenceNumber(nasBytes []byte) uint8 {
	const snOffset = 5
	if len(nasBytes) <= snOffset {
		return 0
	}

	return nasBytes[snOffset]
}

func annotateSecurityHeaderType(nas *naseps.NASResponse, downlink []byte) *naseps.NASResponse {
	if nas == nil {
		return nil
	}

	if sht, err := naseps.SecurityHeader(downlink); err == nil {
		nas.SecurityHeaderType = naseps.SecurityHeaderTypeString(sht)
	}

	return nas
}
