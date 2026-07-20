// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import "github.com/ellanetworks/3gpp-server/internal/s1ap"

type CreateENBRequest struct {
	MMEAddress     string `json:"mme_address"`
	ENBS1Address   string `json:"enb_s1_address"`
	MCC            string `json:"mcc"`
	MNC            string `json:"mnc"`
	TAC            string `json:"tac"`
	ENBID          string `json:"enb_id"`
	ENBIDBitLength int    `json:"enb_id_bit_length,omitempty"`
	Name           string `json:"name"`

	RawS1APPDU *string  `json:"raw_s1ap_pdu,omitempty"`
	WaitFor    []string `json:"wait_for,omitempty"`
	TimeoutMs  int      `json:"timeout_ms,omitempty"`

	SkipS1Setup bool `json:"skip_s1_setup,omitempty"`

	EnableGTPU   bool   `json:"enable_gtpu,omitempty"`
	ENBN3Address string `json:"enb_n3_address,omitempty"`
}

type CreateENBResponse struct {
	ENBID           string             `json:"enb_id"`
	S1SetupResponse *s1ap.S1APResponse `json:"s1_setup_response"`
}

type ENBStateResponse struct {
	ID             string `json:"id"`
	MCC            string `json:"mcc"`
	MNC            string `json:"mnc"`
	TAC            string `json:"tac"`
	ENBID          string `json:"enb_id"`
	ENBIDBitLength int    `json:"enb_id_bit_length,omitempty"`
	Name           string `json:"name"`
}
