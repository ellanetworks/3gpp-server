// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import "github.com/ellanetworks/core/s1ap"

type ENBIDKind = s1ap.ENBIDKind

const (
	ENBIDMacro      = s1ap.ENBIDMacro      // 20-bit
	ENBIDHome       = s1ap.ENBIDHome       // 28-bit
	ENBIDShortMacro = s1ap.ENBIDShortMacro // 18-bit
	ENBIDLongMacro  = s1ap.ENBIDLongMacro  // 21-bit
)

type S1SetupRequestParams struct {
	MCC          string
	MNC          string
	ENBID        uint32
	ENBIDKind    ENBIDKind
	ENBName      string
	TAC          string
	SupportedTAs []SupportedTAParams
}

type SupportedTAParams struct {
	TAC            string
	BroadcastPLMNs []PLMNParams
}

type PLMNParams struct {
	MCC string
	MNC string
}

type S1APResponse struct {
	PDUType     string `json:"pdu_type"`
	MessageType string `json:"message_type"`
	RawHex      string `json:"raw_hex"`

	S1SetupResponse *S1SetupResponseJSON `json:"s1_setup_response,omitempty"`
	S1SetupFailure  *S1SetupFailureJSON  `json:"s1_setup_failure,omitempty"`

	MMEUES1APID                    *int64                      `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID                    *int64                      `json:"enb_ue_s1ap_id,omitempty"`
	NASPDU                         *string                     `json:"nas_pdu,omitempty"`
	ERABSetupItems                 []ERABSetupItemJSON         `json:"erab_setup_items,omitempty"`
	UERadioCapability              *string                     `json:"ue_radio_capability,omitempty"`
	UEAggregateMaxBitRate          *UEAggregateMaxBitRateJSON  `json:"ue_aggregate_max_bit_rate,omitempty"`
	Cause                          *CauseJSON                  `json:"cause,omitempty"`
	CriticalityDiagnostics         *CriticalityDiagnosticsJSON `json:"criticality_diagnostics,omitempty"`
	SecurityContext                *SecurityContextJSON        `json:"security_context,omitempty"`
	ResetConnections               []ResetConnectionJSON       `json:"reset_connections,omitempty"`
	ReplayedUESecurityCapabilities *UESecurityCapabilitiesJSON `json:"replayed_ue_security_capabilities,omitempty"`
	UESecurityCapabilities         *UESecurityCapabilitiesJSON `json:"ue_security_capabilities,omitempty"`
	SourceToTargetContainer        string                      `json:"source_to_target_transparent_container,omitempty"`
	Paging                         *PagingJSON                 `json:"paging,omitempty"`
	ERABModifyItems                []ERABModifyItemJSON        `json:"erab_modify_items,omitempty"`
	ReleasedERABs                  []int                       `json:"released_erabs,omitempty"`
	StatusTransferContainer        string                      `json:"status_transfer_container,omitempty"`

	UnknownIEs []UnknownIEJSON `json:"unknown_ies,omitempty"`
}

type UnknownIEJSON struct {
	ID          int64  `json:"id"`
	Criticality string `json:"criticality"`
	ValueHex    string `json:"value_hex"`
}

type PagingJSON struct {
	MMEC                 uint8  `json:"mmec"`
	MTMSI                uint32 `json:"m_tmsi"`
	UEIdentityIndexValue uint16 `json:"ue_identity_index_value"`
	CNDomain             string `json:"cn_domain"`
}

type UEAggregateMaxBitRateJSON struct {
	DL int64 `json:"dl"`
	UL int64 `json:"ul"`
}

type UESecurityCapabilitiesJSON struct {
	EncryptionAlgorithms          string `json:"encryption_algorithms"`
	IntegrityProtectionAlgorithms string `json:"integrity_protection_algorithms"`
}

type SecurityContextJSON struct {
	NextHopChainingCount int    `json:"next_hop_chaining_count"`
	NextHop              string `json:"next_hop"`
}

type ERABSetupItemJSON struct {
	ERABID                    int    `json:"erab_id"`
	GTPTEID                   uint32 `json:"gtp_teid,omitempty"`
	TransportLayerAddress     string `json:"transport_layer_address,omitempty"`
	TransportLayerAddressIPv6 string `json:"transport_layer_address_ipv6,omitempty"`
}

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

type ServedGUMMEIJSON struct {
	ServedPLMNs    []string `json:"served_plmns"`
	ServedGroupIDs []string `json:"served_group_ids"`
	ServedMMECs    []string `json:"served_mmecs"`
}

type S1SetupFailureJSON struct {
	Cause      CauseJSON `json:"cause"`
	TimeToWait *string   `json:"time_to_wait,omitempty"`
}

// Value indexes the ASN.1 enumeration of the named Cause CHOICE group (TS 36.413 §9.2.1.3).
type CauseJSON struct {
	Group string `json:"group"`
	Value int    `json:"value"`
}

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

type ResetConnectionJSON struct {
	MMEUES1APID *int64 `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID *int64 `json:"enb_ue_s1ap_id,omitempty"`
}
