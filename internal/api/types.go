// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	nasTypes "github.com/ellanetworks/3gpp-server/internal/nas"
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

	// NGSetupIEs, when set, replaces the IEs auto-built from the fields above.
	NGSetupIEs []ngap.IE `json:"ng_setup_ies,omitempty"`

	// SkipNGSetup opens the SCTP association without sending an NG Setup Request,
	// modelling an NG-RAN node that has not completed NG Setup (TS 38.413
	// §8.7.1.1). The response carries no ng_setup_response.
	SkipNGSetup bool `json:"skip_ng_setup,omitempty"`

	// GnBN3Address is the IP the gNB binds and advertises as its downlink GTP-U
	// endpoint (defaults to gnb_n2_address).
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

// SendGnBNGAPRequest is the body for a non-UE-associated NGAP message.
type SendGnBNGAPRequest struct {
	MessageType string `json:"message_type"`

	// RawNGAPPDU, when set, is written verbatim onto the N2 association with no
	// encoding or validation, and message_type is ignored. An empty WaitFor is
	// fire-and-forget.
	RawNGAPPDU *string  `json:"raw_ngap_pdu,omitempty"`
	WaitFor    []string `json:"wait_for,omitempty"`
	TimeoutMs  int      `json:"timeout_ms,omitempty"`

	// An empty ResetUEIDs resets the whole NG interface (ResetType nG-Interface);
	// otherwise only the listed UEs' associations (ResetType partOfNG-Interface).
	ResetUEIDs []string `json:"reset_ue_ids,omitempty"`

	// Path Switch Request reuses these: amf_ue_ngap_id is the existing context's
	// Source AMF UE NGAP ID, ran_ue_ngap_id the new RAN UE NGAP ID, and
	// pdu_sessions the PDU sessions to switch in the downlink.
	AmfUeNgapID *int64               `json:"amf_ue_ngap_id,omitempty"`
	RanUeNgapID *int64               `json:"ran_ue_ngap_id,omitempty"`
	PDUSessions []HandoverPDUSession `json:"pdu_sessions,omitempty"`

	// UESecurityCapabilities are the UE security capabilities a Path Switch
	// Request reports (TS 38.413 §9.3.1.86). Defaults to NR/E-UTRA NEA1-3/NIA1-3
	// when omitted.
	UESecurityCapabilities *UESecurityCapabilitiesInput `json:"ue_security_capabilities,omitempty"`

	// OmitIEs lists protocol IE ids to drop from a built path_switch_request, for
	// sending a structurally-incomplete message.
	OmitIEs []int64 `json:"omit_ies,omitempty"`

	// FailedPDUSessions are reported as failed-to-setup in a Handover Request
	// Acknowledge or Path Switch Request.
	FailedPDUSessions []int64 `json:"failed_pdu_sessions,omitempty"`

	// Cause is the radio-network Cause (TS 38.413 §9.3.1.2) a handover_failure
	// carries. Defaults to ho-failure-in-target-5GC-ngran-node-or-target-system.
	Cause *int64 `json:"cause,omitempty"`
}

// MigrateUERequest moves a UE's context to another gNB's association, modelling
// the UE arriving at the target after an N2 handover. The NGAP IDs become the
// ones in use on the target.
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

// DLTeid and DLIP are the target gNB's downlink GTP tunnel. RawTransfer (hex)
// replaces the built transfer verbatim.
type HandoverPDUSession struct {
	ID          int64   `json:"id"`
	DLTeid      uint32  `json:"dl_teid,omitempty"`
	DLIP        string  `json:"dl_ip,omitempty"`
	RawTransfer *string `json:"raw_transfer,omitempty"`
}

// UESecurityCapabilitiesInput overrides the UE security capability algorithm
// bitmaps a Path Switch Request reports. Each field is a 4-hex-digit (16-bit)
// big-endian bitmap; omitted fields default to NEA1-3 / NIA1-3 (NR) and 0
// (E-UTRA).
type UESecurityCapabilitiesInput struct {
	NREncryption    string `json:"nr_encryption,omitempty"`
	NRIntegrity     string `json:"nr_integrity,omitempty"`
	EUTRAEncryption string `json:"eutra_encryption,omitempty"`
	EUTRAIntegrity  string `json:"eutra_integrity,omitempty"`
}

// AwaitRequest waits for a downlink NGAP message the core sends without a
// triggering uplink.
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

type SendNGAPRequest = nasTypes.NASRequest

type SendNGAPResponse struct {
	NGAP *ngap.NGAPResponse    `json:"ngap"`
	NAS  *nasTypes.NASResponse `json:"nas,omitempty"`
}
