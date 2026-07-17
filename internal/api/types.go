// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"github.com/ellanetworks/3gpp-server/internal/ngap"
)

type CreateGnBRequest struct {
	AMFAddress   string `json:"amf_address"`
	GnBN2Address string `json:"gnb_n2_address"`
	MCC          string `json:"mcc"`
	MNC          string `json:"mnc"`
	TAC          string `json:"tac"`
	GnbID        string `json:"gnb_id"`
	Name         string `json:"name"`
	SST          int32  `json:"sst"`
	SD           string `json:"sd,omitempty"`

	Slices []SliceInput `json:"slices,omitempty"`

	NGSetupIEs  []ngap.IE `json:"ng_setup_ies,omitempty"`
	SkipNGSetup bool      `json:"skip_ng_setup,omitempty"`

	RawNGAPPDU *string  `json:"raw_ngap_pdu,omitempty"`
	WaitFor    []string `json:"wait_for,omitempty"`
	TimeoutMs  int      `json:"timeout_ms,omitempty"`

	EnableGTPU   bool   `json:"enable_gtpu,omitempty"`
	GnBN3Address string `json:"gnb_n3_address,omitempty"`
}

type SliceInput struct {
	SST int32  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

type CreateGnBResponse struct {
	GnBID           string             `json:"gnb_id"`
	NGSetupResponse *ngap.NGAPResponse `json:"ng_setup_response"`
}

type SendGnBNGAPRequest struct {
	MessageType string `json:"message_type"`

	RawNGAPPDU *string  `json:"raw_ngap_pdu,omitempty"`
	WaitFor    []string `json:"wait_for,omitempty"`
	TimeoutMs  int      `json:"timeout_ms,omitempty"`

	ResetUEIDs []string `json:"reset_ue_ids,omitempty"`

	AmfUeNgapID *int64               `json:"amf_ue_ngap_id,omitempty"`
	RanUeNgapID *int64               `json:"ran_ue_ngap_id,omitempty"`
	PDUSessions []HandoverPDUSession `json:"pdu_sessions,omitempty"`

	UESecurityCapabilities *UESecurityCapabilitiesInput `json:"ue_security_capabilities,omitempty"`

	OmitIEs           []int64 `json:"omit_ies,omitempty"`
	FailedPDUSessions []int64 `json:"failed_pdu_sessions,omitempty"`
	Cause             *int64  `json:"cause,omitempty"`
}

type MigrateUERequest struct {
	TargetGnbID string `json:"target_gnb_id"`
	RanUeNgapID *int64 `json:"ran_ue_ngap_id,omitempty"`
	AmfUeNgapID *int64 `json:"amf_ue_ngap_id,omitempty"`
}

type MigrateUEResponse struct {
	UEID        string `json:"ue_id"`
	GnBID       string `json:"gnb_id"`
	RanUeNgapID int64  `json:"ran_ue_ngap_id"`
	AmfUeNgapID int64  `json:"amf_ue_ngap_id"`
}

type HandoverPDUSession struct {
	ID          int64   `json:"id"`
	DLTeid      uint32  `json:"dl_teid,omitempty"`
	DLIP        string  `json:"dl_ip,omitempty"`
	RawTransfer *string `json:"raw_transfer,omitempty"`
}

type UESecurityCapabilitiesInput struct {
	NREncryption    string `json:"nr_encryption,omitempty"`
	NRIntegrity     string `json:"nr_integrity,omitempty"`
	EUTRAEncryption string `json:"eutra_encryption,omitempty"`
	EUTRAIntegrity  string `json:"eutra_integrity,omitempty"`
}

type AwaitRequest struct {
	MessageTypes []string `json:"message_types"`
	TimeoutMs    int      `json:"timeout_ms,omitempty"`
}

type GnBStateResponse struct {
	ID    string `json:"id"`
	MCC   string `json:"mcc"`
	MNC   string `json:"mnc"`
	TAC   string `json:"tac"`
	GnbID string `json:"gnb_id"`
	Name  string `json:"name"`
	SST   int32  `json:"sst"`
	SD    string `json:"sd,omitempty"`
}

type CreateUERequest struct {
	SUPI             string `json:"supi"`
	K                string `json:"k"`
	OPc              string `json:"opc"`
	Amf              string `json:"amf,omitempty"`
	Sqn              string `json:"sqn,omitempty"`
	SST              int32  `json:"sst,omitempty"`
	SD               string `json:"sd,omitempty"`
	DNN              string `json:"dnn,omitempty"`
	RoutingIndicator string `json:"routing_indicator,omitempty"`
	ProtectionScheme string `json:"protection_scheme,omitempty"`
	PublicKeyID      string `json:"public_key_id,omitempty"`
	PublicKeyHex     string `json:"public_key_hex,omitempty"`
	PDUSessionID     uint8  `json:"pdu_session_id,omitempty"`
	PDUSessionType   uint8  `json:"pdu_session_type,omitempty"`
	IMEISV           string `json:"imeisv,omitempty"`
}

type CreateUEResponse struct {
	UEID        string `json:"ue_id"`
	SUPI        string `json:"supi"`
	SUCI        string `json:"suci"`
	RanUeNgapID int64  `json:"ran_ue_ngap_id"`
}

type UEStateResponse struct {
	ID               string `json:"id"`
	SUPI             string `json:"supi"`
	SUCI             string `json:"suci"`
	MCC              string `json:"mcc"`
	MNC              string `json:"mnc"`
	RanUeNgapID      int64  `json:"ran_ue_ngap_id"`
	AmfUeNgapID      int64  `json:"amf_ue_ngap_id"`
	K                string `json:"k"`
	OPc              string `json:"opc"`
	Amf              string `json:"amf"`
	Sqn              string `json:"sqn"`
	Snn              string `json:"snn"`
	DNN              string `json:"dnn,omitempty"`
	SST              int32  `json:"sst,omitempty"`
	SD               string `json:"sd,omitempty"`
	ProtectionScheme string `json:"protection_scheme"`
	RoutingIndicator string `json:"routing_indicator"`
	IMEISV           string `json:"imeisv,omitempty"`
}

type PatchUERequest struct {
	K           *string `json:"k,omitempty"`
	OPc         *string `json:"opc,omitempty"`
	Amf         *string `json:"amf,omitempty"`
	Sqn         *string `json:"sqn,omitempty"`
	AmfUeNgapID *int64  `json:"amf_ue_ngap_id,omitempty"`
	DNN         *string `json:"dnn,omitempty"`
	SST         *int32  `json:"sst,omitempty"`
	SD          *string `json:"sd,omitempty"`
	IMEISV      *string `json:"imeisv,omitempty"`
}
