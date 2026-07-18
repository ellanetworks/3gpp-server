// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
)

type CreateENBUERequest struct {
	IMSI                string `json:"imsi"`
	IMEISV              string `json:"imeisv,omitempty"`
	K                   string `json:"k"`
	OPc                 string `json:"opc"`
	AMF                 string `json:"amf,omitempty"`
	SQN                 string `json:"sqn,omitempty"`
	UENetworkCapability string `json:"ue_network_capability,omitempty"`
}

type CreateENBUEResponse struct {
	UEID        string `json:"ue_id"`
	ENBUES1APID uint32 `json:"enb_ue_s1ap_id"`
}

type SendENBUES1APRequest struct {
	MessageType string `json:"message_type"`

	PDNType     uint8 `json:"pdn_type,omitempty"`
	AttachType  uint8 `json:"attach_type,omitempty"`
	ForeignGUTI bool  `json:"foreign_guti,omitempty"`

	RawNASPDU  *string `json:"raw_nas_pdu,omitempty"`
	CorruptMAC bool    `json:"corrupt_mac,omitempty"`

	MMEUES1APIDOverride           *uint32 `json:"mme_ue_s1ap_id_override,omitempty"`
	ENBUES1APIDOverride           *uint32 `json:"enb_ue_s1ap_id_override,omitempty"`
	RRCEstablishmentCauseOverride *int64  `json:"rrc_establishment_cause,omitempty"`

	ReplayLast        bool    `json:"replay_last,omitempty"`
	SwitchOff         bool    `json:"switch_off,omitempty"`
	ReleaseCause      *int    `json:"release_cause,omitempty"`
	UERadioCapability string  `json:"ue_radio_capability,omitempty"`
	MTMSIOverride     *uint32 `json:"mtmsi,omitempty"`
	NASCountOverride  *uint32 `json:"nas_count,omitempty"`
	EPSUpdateType     uint8   `json:"eps_update_type,omitempty"`

	PathSwitchERABID *uint8  `json:"path_switch_erab_id,omitempty"`
	DuplicateERAB    bool    `json:"duplicate_erab,omitempty"`
	PathSwitchEEA    *uint16 `json:"path_switch_eea,omitempty"`
	PathSwitchEIA    *uint16 `json:"path_switch_eia,omitempty"`

	APN               string `json:"apn,omitempty"`
	PTI               *uint8 `json:"pti,omitempty"`
	RequestEBI        *uint8 `json:"request_ebi,omitempty"`
	LinkedEBI         *uint8 `json:"linked_ebi,omitempty"`
	EPSBearerIdentity *uint8 `json:"eps_bearer_identity,omitempty"`
	ESMCause          *uint8 `json:"esm_cause,omitempty"`
	WithholdAccept    bool   `json:"withhold_accept,omitempty"`

	RESOverride *string `json:"res_override,omitempty"`
	Cause       *int    `json:"cause,omitempty"`

	TargetENBID             *string `json:"target_enb_id,omitempty"`
	HandoverRequiredCause   *int    `json:"handover_required_cause,omitempty"`
	HandoverCancelCause     *int    `json:"handover_cancel_cause,omitempty"`
	StatusTransferContainer *string `json:"status_transfer_container,omitempty"`

	TimeoutMs int `json:"timeout_ms,omitempty"`
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

	Cause  *int    `json:"cause,omitempty"`
	CellID *uint32 `json:"cell_id,omitempty"`
}

type HandoverERAB struct {
	ID     uint8  `json:"id"`
	DLTeid uint32 `json:"dl_teid,omitempty"`
	DLIP   string `json:"dl_ip,omitempty"`
}

type MigrateENBUERequest struct {
	TargetENBID string  `json:"target_enb_id"`
	MMEUES1APID *uint32 `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID *uint32 `json:"enb_ue_s1ap_id,omitempty"`
}

type ENBUEBearer struct {
	EBI  uint8  `json:"ebi"`
	APN  string `json:"apn"`
	UEIP string `json:"ue_ip"`
}

type ENBUEStateResponse struct {
	UEID           string        `json:"ue_id"`
	IMSI           string        `json:"imsi"`
	IMEISV         string        `json:"imeisv,omitempty"`
	UEIP           string        `json:"ue_ip"`
	SecurityActive bool          `json:"security_active"`
	MMEUES1APID    uint32        `json:"mme_ue_s1ap_id"`
	ENBUES1APID    uint32        `json:"enb_ue_s1ap_id"`
	DefaultEBI     uint8         `json:"default_ebi"`
	Bearers        []ENBUEBearer `json:"bearers"`
}

type MigrateENBUEResponse struct {
	UEID        string `json:"ue_id"`
	ENBID       string `json:"enb_id"`
	MMEUES1APID uint32 `json:"mme_ue_s1ap_id"`
	ENBUES1APID uint32 `json:"enb_ue_s1ap_id"`
}

type SendENBUES1APResponse struct {
	S1AP        *s1ap.S1APResponse  `json:"s1ap,omitempty"`
	NAS         *naseps.NASResponse `json:"nas,omitempty"`
	MACVerified *bool               `json:"mac_verified,omitempty"`
}
