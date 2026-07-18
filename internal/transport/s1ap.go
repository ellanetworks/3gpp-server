// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	s1apCodec "github.com/ellanetworks/3gpp-server/internal/s1ap"
)

// sctp.SndRcvInfo carries the PPID in network byte order, so S1AP's 18 (TS 36.412) is stored pre-swapped.
const s1apPPID uint32 = 18 << 24

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
