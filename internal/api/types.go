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

	// Override: if provided, send these IEs instead of auto-building from the fields above.
	NGSetupIEs []ngap.IE `json:"ng_setup_ies,omitempty"`

	// SkipNGSetup opens the SCTP association but does not send an NG Setup
	// Request, modelling an NG-RAN node that has not completed NG Setup. The
	// response carries no ng_setup_response. Used to test that the AMF refuses to
	// serve NGAP procedures before NG Setup (TS 38.413 §8.7.1.1).
	SkipNGSetup bool `json:"skip_ng_setup,omitempty"`

	// EnableGTPU binds an N3 GTP-U endpoint so the gNB terminates the user-plane
	// data path. GnBN3Address is the N3 IP it binds and advertises as its
	// downlink GTP-U endpoint (defaults to gnb_n2_address).
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

// SendGnBNGAPRequest is the JSON body for a gNB-level (non-UE-associated) NGAP
// message sent on the gNB's existing N2 association.
type SendGnBNGAPRequest struct {
	MessageType string `json:"message_type"`

	// RawNGAPPDU, when set, is written verbatim onto the N2 association with no
	// encoding or validation, and message_type is ignored — letting a test send
	// any NGAP PDU, well-formed or not. WaitFor lists downlink message types to
	// block for (empty = fire-and-forget); TimeoutMs bounds that wait.
	RawNGAPPDU *string  `json:"raw_ngap_pdu,omitempty"`
	WaitFor    []string `json:"wait_for,omitempty"`
	TimeoutMs  int      `json:"timeout_ms,omitempty"`

	// NG Reset: when ResetUEIDs is empty the whole NG interface is reset
	// (ResetType nG-Interface); otherwise only the listed UEs' associations are
	// reset (ResetType partOfNG-Interface).
	ResetUEIDs []string `json:"reset_ue_ids,omitempty"`

	// Handover (target gNB side): the AMF/RAN UE NGAP IDs identifying the UE
	// association, and the admitted PDU sessions for Handover Request Acknowledge.
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
	// sending a structurally-incomplete message (e.g. missing a mandatory IE) to
	// probe the AMF's error handling.
	OmitIEs []int64 `json:"omit_ies,omitempty"`

	// FailedPDUSessions are PDU sessions reported as failed-to-setup in a
	// Handover Request Acknowledge or Path Switch Request (partial-admission
	// testing).
	FailedPDUSessions []int64 `json:"failed_pdu_sessions,omitempty"`

	// Cause is the radio-network Cause (TS 38.413 §9.3.1.2) a handover_failure
	// carries. Defaults to ho-failure-in-target-5GC-ngran-node-or-target-system.
	Cause *int64 `json:"cause,omitempty"`
}

// MigrateUERequest moves a UE's context to another gNB's association, modelling
// the UE arriving at the target after an N2 handover. The RAN/AMF UE NGAP IDs
// become the ones in use on the target.
type MigrateUERequest struct {
	TargetGnbID string `json:"target_gnb_id"`
	RanUeNgapID *int64 `json:"ran_ue_ngap_id,omitempty"`
	AmfUeNgapID *int64 `json:"amf_ue_ngap_id,omitempty"`
}

// HandoverPDUSession is an admitted PDU session in a Handover Request
// Acknowledge, carrying the target gNB's downlink GTP tunnel. RawTransfer (hex)
// overrides the built transfer verbatim, for crafting malformed transfers.
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

// AwaitRequest waits for an unsolicited downlink NGAP message (one the core
// sends without a triggering uplink, e.g. Handover Request, Handover Command,
// UE Context Release Command) to arrive on the gNB's N2 association.
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
