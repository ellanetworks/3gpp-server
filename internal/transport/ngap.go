// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	"github.com/free5gc/ngap"

	ngapCodec "github.com/ellanetworks/3gpp-server/internal/ngap"
)

// NGAPTransport is an NGAP association to an AMF (PPID 60, TS 38.412).
type NGAPTransport struct {
	*framed[ngapCodec.NGAPResponse]
}

func DialNGAP(localAddr, remoteAddr string) (*NGAPTransport, error) {
	f, err := dialFramed(
		localAddr, remoteAddr, ngap.PPID,
		ngapCodec.Decode,
		func(r *ngapCodec.NGAPResponse) string { return r.MessageType },
	)
	if err != nil {
		return nil, err
	}

	return &NGAPTransport{f}, nil
}
