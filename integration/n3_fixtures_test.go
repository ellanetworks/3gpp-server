// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

type n3Transport struct {
	name  string
	ranN3 string
	upfN3 string
}

var (
	n3IPv4 = n3Transport{name: "n3v4", ranN3: "10.3.0.3", upfN3: "10.3.0.2"}
	n3IPv6 = n3Transport{name: "n3v6", ranN3: "fd00:3::3", upfN3: "fd00:3::2"}
)

const dnResponderIP = "10.6.0.10"

const udpEchoPort = 7

// badTEID is a non-zero TEID with no PDR at the UPF.
const badTEID = 0xFFFFFFFE
