// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import "github.com/ellanetworks/3gpp-server/internal/s1ap"

type CreateENBRequest struct {
	MMEAddress   string `json:"mme_address"`
	ENBS1Address string `json:"enb_s1_address"`
	MCC          string `json:"mcc"`
	MNC          string `json:"mnc"`
	TAC          string `json:"tac"`
	ENBID        uint32 `json:"enb_id"`
	Name         string `json:"name"`

	// RawS1APPDU, when set, is written verbatim onto the S1-MME association in
	// place of a built S1 Setup Request, with no encoding or validation — letting
	// a test send any S1AP PDU, well-formed or not. The other fields still seed
	// the stored eNB context. WaitFor lists downlink message types to block for
	// (defaults to the S1 Setup outcomes plus ErrorIndication); for the raw path a
	// timeout returns a null response rather than an error, since a compliant MME
	// may silently drop a malformed PDU. TimeoutMs bounds the wait.
	RawS1APPDU *string  `json:"raw_s1ap_pdu,omitempty"`
	WaitFor    []string `json:"wait_for,omitempty"`
	TimeoutMs  int      `json:"timeout_ms,omitempty"`

	// SkipS1Setup opens the SCTP association without sending an S1 Setup Request.
	SkipS1Setup bool `json:"skip_s1_setup,omitempty"`

	// EnableGTPU binds an S1-U GTP-U endpoint so the eNB terminates the user-plane
	// data path. ENBN3Address is the IP it binds (defaults to enb_s1_address).
	EnableGTPU   bool   `json:"enable_gtpu,omitempty"`
	ENBN3Address string `json:"enb_n3_address,omitempty"`
}

type CreateENBResponse struct {
	ENBID string `json:"enb_id"`
	// Response is the first matching downlink received (S1 Setup Response/Failure,
	// or whatever a raw send elicits), or null if none arrived within the timeout.
	Response *s1ap.S1APResponse `json:"response"`
}

type ENBStateResponse struct {
	ID    string `json:"id"`
	MCC   string `json:"mcc"`
	MNC   string `json:"mnc"`
	TAC   string `json:"tac"`
	ENBID uint32 `json:"enb_id"`
	Name  string `json:"name"`
}
