// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// N3 / S1-U user-plane fixtures. The GTP-U transport family is RAT-neutral (TS
// 29.281 applies unchanged to S1-U and N3), so the tunnel endpoints and the
// data-network responder are shared by the 4G and 5G user-plane tests.

package integration_test

// n3Transport selects the IP family of the GTP-U tunnel between the emulated
// RAN node and the UPF. N2/S1-MME signalling stays IPv4; only the GTP-U
// transport varies.
type n3Transport struct {
	name  string // subtest label
	ranN3 string // the RAN node's N3/S1-U bind/source address
	upfN3 string // the UPF's N3/S1-U address (GTP-U peer)
}

var (
	n3IPv4 = n3Transport{name: "n3v4", ranN3: "10.3.0.3", upfN3: "10.3.0.2"}
	n3IPv6 = n3Transport{name: "n3v6", ranN3: "fd00:3::3", upfN3: "fd00:3::2"}
)

// dnResponderIP is the data-network host on N6 (compose sidecar) that replies to
// ICMP echo and echoes UDP on udpEchoPort.
const dnResponderIP = "10.6.0.10"

// udpEchoPort is the port the dn-responder echoes UDP datagrams on (socat).
const udpEchoPort = 7

// badTEID is a non-zero TEID with no PDR at the UPF.
const badTEID = 0xFFFFFFFE
