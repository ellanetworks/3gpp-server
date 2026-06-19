// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	s1apCodec "github.com/ellanetworks/3gpp-server/internal/s1ap"
)

// s1apPPID is the SCTP payload protocol identifier for S1AP, 18 (TS 36.412).
// The ishidawataru/sctp SndRcvInfo carries the PPID in network byte order, so it
// is stored pre-swapped — matching free5gc's ngap.PPID (0x3c000000 for 60).
const s1apPPID uint32 = 18 << 24

// S1APTransport is an S1AP association to an MME (PPID 18, TS 36.412).
type S1APTransport struct {
	*framed[s1apCodec.S1APResponse]
}

func DialS1AP(localAddr, remoteAddr string) (*S1APTransport, error) {
	f, err := dialFramed(
		localAddr, remoteAddr, s1apPPID,
		s1apCodec.Decode,
		func(r *s1apCodec.S1APResponse) string { return r.MessageType },
	)
	if err != nil {
		return nil, err
	}

	return &S1APTransport{f}, nil
}
