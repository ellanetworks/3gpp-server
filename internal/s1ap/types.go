// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import "github.com/ellanetworks/core/s1ap"

// ENBIDKind selects an ENB-ID CHOICE alternative (TS 36.413 §9.2.1.37),
// re-exported so callers build variants without importing the core codec.
type ENBIDKind = s1ap.ENBIDKind

const (
	ENBIDMacro      = s1ap.ENBIDMacro      // 20-bit
	ENBIDHome       = s1ap.ENBIDHome       // 28-bit
	ENBIDShortMacro = s1ap.ENBIDShortMacro // 18-bit
	ENBIDLongMacro  = s1ap.ENBIDLongMacro  // 21-bit
)

// S1SetupRequestParams are the inputs to build an S1 Setup Request
// (TS 36.413 §9.1.8.4). With SupportedTAs empty, a single TA whose only
// broadcast PLMN equals the eNB PLMN is advertised; ENBIDKind zero is a macro
// eNB-ID.
type S1SetupRequestParams struct {
	MCC          string
	MNC          string
	ENBID        uint32
	ENBIDKind    ENBIDKind
	ENBName      string
	TAC          uint16
	SupportedTAs []SupportedTAParams
}

// SupportedTAParams is one supported TA. An empty BroadcastPLMNs advertises the
// eNB's own PLMN.
type SupportedTAParams struct {
	TAC            uint16
	BroadcastPLMNs []PLMNParams
}

type PLMNParams struct {
	MCC string
	MNC string
}

// S1APResponse is the decoded form of a downlink S1AP PDU returned as JSON.
type S1APResponse struct {
	PDUType     string `json:"pdu_type"`
	MessageType string `json:"message_type"`
	RawHex      string `json:"raw_hex"`

	S1SetupResponse *S1SetupResponseJSON `json:"s1_setup_response,omitempty"`
	S1SetupFailure  *S1SetupFailureJSON  `json:"s1_setup_failure,omitempty"`

	// UE-associated fields, set on Downlink NAS Transport, Initial Context Setup
	// Request, and UE Context Release Command.
	MMEUES1APID *int64  `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID *int64  `json:"enb_ue_s1ap_id,omitempty"`
	NASPDU      *string `json:"nas_pdu,omitempty"` // hex-encoded inner NAS message

	// Set on an Initial Context Setup Request; the default bearer's item carries
	// the Attach Accept as its NAS-PDU.
	ERABSetupItems []ERABSetupItemJSON `json:"erab_setup_items,omitempty"`

	// Hex-encoded (TS 23.401 §5.11.2).
	UERadioCapability *string `json:"ue_radio_capability,omitempty"`

	// Set on an Initial Context Setup Request (TS 36.413 §9.2.1.20).
	UEAggregateMaxBitRate *UEAggregateMaxBitRateJSON `json:"ue_aggregate_max_bit_rate,omitempty"`

	// Set on an Error Indication (TS 36.413 §9.1.4.3) and a Path Switch Request
	// Failure (§9.1.5.10).
	Cause *CauseJSON `json:"cause,omitempty"`

	// Set on an Error Indication or S1 Setup Failure carrying one
	// (TS 36.413 §9.2.1.21).
	CriticalityDiagnostics *CriticalityDiagnosticsJSON `json:"criticality_diagnostics,omitempty"`

	// Set on a Path Switch Request Acknowledge: the {NCC, NH} the target eNB uses
	// to derive the next K_eNB (TS 33.401 §7.2.8).
	SecurityContext *SecurityContextJSON `json:"security_context,omitempty"`

	// Set on a Reset Acknowledge: the connections the MME reset, echoed for a
	// partial reset (TS 36.413 §8.7.1.2.1).
	ResetConnections []ResetConnectionJSON `json:"reset_connections,omitempty"`

	// Set on a Path Switch Request Acknowledge only when the MME's stored UE
	// security capabilities differ from those the target eNB reported, so the eNB
	// corrects its context (TS 36.413 §9.1.5.9).
	ReplayedUESecurityCapabilities *UESecurityCapabilitiesJSON `json:"replayed_ue_security_capabilities,omitempty"`

	// Set on a PAGING (TS 36.413 §9.1.6).
	Paging *PagingJSON `json:"paging,omitempty"`

	// Set on an E-RAB Modify Request (TS 36.413 §9.1.3.3); the default bearer's
	// item carries the Modify EPS Bearer Context Request as its NAS-PDU.
	ERABModifyItems []ERABModifyItemJSON `json:"erab_modify_items,omitempty"`

	// Set on a Handover Command: the E-RABs the target did not admit, whose PDN
	// connections the source releases (TS 36.413 §9.1.5.2).
	ReleasedERABs []int `json:"released_erabs,omitempty"`

	// The opaque PDCP status container an MME STATUS TRANSFER relays from the
	// source eNB to the target (TS 36.413 §8.4.7), hex.
	StatusTransferContainer string `json:"status_transfer_container,omitempty"`

	// The ProtocolIEs the received message carries that its message type does not
	// model, in wire order.
	UnknownIEs []UnknownIEJSON `json:"unknown_ies,omitempty"`
}

// UnknownIEJSON is one ProtocolIE-Field the message type does not model.
// Criticality instructs a receiver how to act on an IE it does not comprehend
// (TS 36.413 §10.3.2), so it is reported with the IE.
type UnknownIEJSON struct {
	ID          int64  `json:"id"`
	Criticality string `json:"criticality"`
	ValueHex    string `json:"value_hex"`
}

// PagingJSON is the decoded PAGING content (TS 36.413 §9.1.6). The UE identity
// index is IMSI mod 1024.
type PagingJSON struct {
	MMEC                 uint8  `json:"mmec"`
	MTMSI                uint32 `json:"m_tmsi"`
	UEIdentityIndexValue uint16 `json:"ue_identity_index_value"`
	CNDomain             string `json:"cn_domain"`
}

// UEAggregateMaxBitRateJSON is the UE-AMBR, in bits per second.
type UEAggregateMaxBitRateJSON struct {
	DL int64 `json:"dl"`
	UL int64 `json:"ul"`
}

// UESecurityCapabilitiesJSON is the S1AP EPS encryption/integrity algorithm
// bitmaps (TS 36.413 §9.2.1.40).
type UESecurityCapabilitiesJSON struct {
	EncryptionAlgorithms          int `json:"encryption_algorithms"`
	IntegrityProtectionAlgorithms int `json:"integrity_protection_algorithms"`
}

// SecurityContextJSON is the {NCC, NH} key-chain material from a Path Switch
// Request Acknowledge (TS 36.413 §9.2.1.41).
type SecurityContextJSON struct {
	NextHopChainingCount int    `json:"next_hop_chaining_count"`
	NextHop              string `json:"next_hop"` // hex-encoded 256-bit NH
}

// ERABSetupItemJSON is an E-RAB and the S-GW S1-U endpoint the eNB sends uplink
// user data to. A dual-stack endpoint signals both addresses (TS 36.414 §5.3),
// so both are surfaced.
type ERABSetupItemJSON struct {
	ERABID                    int    `json:"erab_id"`
	GTPTEID                   uint32 `json:"gtp_teid,omitempty"`
	TransportLayerAddress     string `json:"transport_layer_address,omitempty"`
	TransportLayerAddressIPv6 string `json:"transport_layer_address_ipv6,omitempty"`
}

// ERABModifyItemJSON is one E-RAB with its new E-RAB-level QoS
// (TS 36.413 §9.2.1.15).
type ERABModifyItemJSON struct {
	ERABID           int `json:"erab_id"`
	QCI              int `json:"qci"`
	ARPPriorityLevel int `json:"arp_priority_level"`
}

type S1SetupResponseJSON struct {
	MMEName             string             `json:"mme_name,omitempty"`
	ServedGUMMEIs       []ServedGUMMEIJSON `json:"served_gummeis"`
	RelativeMMECapacity int                `json:"relative_mme_capacity"`
}

// ServedGUMMEIJSON is one served GUMMEI item; each value is a hex octet string.
type ServedGUMMEIJSON struct {
	ServedPLMNs    []string `json:"served_plmns"`
	ServedGroupIDs []string `json:"served_group_ids"`
	ServedMMECs    []string `json:"served_mmecs"`
}

type S1SetupFailureJSON struct {
	Cause      CauseJSON `json:"cause"`
	TimeToWait *string   `json:"time_to_wait,omitempty"`
}

// CauseJSON identifies a Cause CHOICE group and the enumeration index within it
// (TS 36.413 §9.2.1.3).
type CauseJSON struct {
	Group string `json:"group"`
	Value int    `json:"value"`
}

// CriticalityDiagnosticsJSON reports which IEs or procedure a receiver could not
// handle (TS 36.413 §9.2.1.21).
type CriticalityDiagnosticsJSON struct {
	ProcedureCode             *int64                        `json:"procedure_code,omitempty"`
	TriggeringMessage         *string                       `json:"triggering_message,omitempty"`
	ProcedureCriticality      *string                       `json:"procedure_criticality,omitempty"`
	IEsCriticalityDiagnostics []IECriticalityDiagnosticJSON `json:"ies_criticality_diagnostics,omitempty"`
}

type IECriticalityDiagnosticJSON struct {
	IECriticality string `json:"ie_criticality"`
	IEID          int64  `json:"ie_id"`
	TypeOfError   string `json:"type_of_error"`
}

// ResetConnectionJSON is one UE-associated logical S1 connection
// (TS 36.413 §9.2.3.20).
type ResetConnectionJSON struct {
	MMEUES1APID *int64 `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID *int64 `json:"enb_ue_s1ap_id,omitempty"`
}
