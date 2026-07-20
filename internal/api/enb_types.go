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

	DefaultPagingDRX *int `json:"default_paging_drx,omitempty"`

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

type SendENBS1APRequest struct {
	MessageType string `json:"message_type"`

	RawS1APPDU *string  `json:"raw_s1ap_pdu,omitempty"`
	WaitFor    []string `json:"wait_for,omitempty"`
	TimeoutMs  int      `json:"timeout_ms,omitempty"`

	ResetUEIDs []string `json:"reset_ue_ids,omitempty"`

	MMEUES1APID *uint32 `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID *uint32 `json:"enb_ue_s1ap_id,omitempty"`

	Admitted    []HandoverERAB `json:"admitted_erabs,omitempty"`
	FailedERABs []uint8        `json:"failed_erabs,omitempty"`
	ERABs       []HandoverERAB `json:"erabs,omitempty"`

	DuplicateERAB bool    `json:"duplicate_erab,omitempty"`
	PathSwitchEEA *uint16 `json:"path_switch_eea,omitempty"`
	PathSwitchEIA *uint16 `json:"path_switch_eia,omitempty"`

	Cause  *int    `json:"cause,omitempty"`
	CellID *uint32 `json:"cell_id,omitempty"`
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
