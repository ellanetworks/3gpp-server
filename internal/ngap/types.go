// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import "encoding/json"

type NGAPMessage struct {
	ProcedureCode int64  `json:"procedure_code"`
	PDUType       string `json:"pdu_type"`
	Criticality   string `json:"criticality"`
	IEs           []IE   `json:"ies,omitempty"`
}

type IE struct {
	ID          int64           `json:"id"`
	Criticality string          `json:"criticality,omitempty"`
	Value       json.RawMessage `json:"value,omitempty"`

	GlobalRANNodeID         *GlobalRANNodeIDJSON         `json:"global_ran_node_id,omitempty"`
	RANNodeName             *string                      `json:"ran_node_name,omitempty"`
	SupportedTAList         *SupportedTAListJSON         `json:"supported_ta_list,omitempty"`
	DefaultPagingDRX        *int64                       `json:"default_paging_drx,omitempty"`
	RANUENGAPID             *int64                       `json:"ran_ue_ngap_id,omitempty"`
	AMFUENGAPID             *int64                       `json:"amf_ue_ngap_id,omitempty"`
	NasPDU                  *string                      `json:"nas_pdu,omitempty"`
	UserLocationInformation *UserLocationInformationJSON `json:"user_location_information,omitempty"`
	RRCEstablishmentCause   *int64                       `json:"rrc_establishment_cause,omitempty"`
	FiveGSTMSI              *FiveGSTMSIJSON              `json:"five_g_s_tmsi,omitempty"`
	UEContextRequest        *int64                       `json:"ue_context_request,omitempty"`
	Cause                   *CauseJSON                   `json:"cause,omitempty"`
	AMFName                 *string                      `json:"amf_name,omitempty"`
	ServedGUAMIList         []ServedGUAMIJSON            `json:"served_guami_list,omitempty"`
	RelativeAMFCapacity     *int64                       `json:"relative_amf_capacity,omitempty"`
	PLMNSupportList         []PLMNSupportJSON            `json:"plmn_support_list,omitempty"`
	UERetentionInformation  *int64                       `json:"ue_retention_information,omitempty"`
	CriticalityDiagnostics  *CriticalityDiagnosticsJSON  `json:"criticality_diagnostics,omitempty"`
	TimeToWait              *string                      `json:"time_to_wait,omitempty"`

	AMFSetID             *string                `json:"amf_set_id_ie,omitempty"`
	AllowedNSSAI         []AllowedNSSAIItemJSON `json:"allowed_nssai,omitempty"`
	SelectedPLMNIdentity *string                `json:"selected_plmn_identity,omitempty"`

	OldAMF                  *string                      `json:"old_amf,omitempty"`
	RANPagingPriority       *int64                       `json:"ran_paging_priority,omitempty"`
	MobilityRestrictionList *MobilityRestrictionListJSON `json:"mobility_restriction_list,omitempty"`
	IndexToRFSP             *int64                       `json:"index_to_rfsp,omitempty"`
	UEAggregateMaxBitRate   *UEAggregateMaxBitRateJSON   `json:"ue_aggregate_max_bit_rate,omitempty"`

	UERadioCapability       *string                     `json:"ue_radio_capability,omitempty"`
	PDUSessionSetupItems    []PDUSessionSetupItemJSON   `json:"pdu_session_setup_items,omitempty"`
	PDUSessionIDs           []int64                     `json:"pdu_session_ids,omitempty"`
	ReleasePDUSessionIDs    []int64                     `json:"release_pdu_session_ids,omitempty"`
	NextHopChainingCount    *int64                      `json:"next_hop_chaining_count,omitempty"`
	NextHop                 *string                     `json:"next_hop,omitempty"`
	UESecurityCapabilities  *UESecurityCapabilitiesJSON `json:"ue_security_capabilities,omitempty"`
	RANStatusTransfer       *RANStatusTransferJSON      `json:"ran_status_transfer,omitempty"`
	SourceToTargetContainer *string                     `json:"source_to_target_transparent_container,omitempty"`
}

type COUNTValueJSON struct {
	PDCPSN int64 `json:"pdcp_sn"`
	HFN    int64 `json:"hfn"`
}

type DRBStatusTransferItemJSON struct {
	DRBID   int64           `json:"drb_id"`
	ULCount *COUNTValueJSON `json:"ul_count,omitempty"`
	DLCount *COUNTValueJSON `json:"dl_count,omitempty"`
}

type RANStatusTransferJSON struct {
	DRBs []DRBStatusTransferItemJSON `json:"drbs_subject_to_status_transfer"`
}

type UESecurityCapabilitiesJSON struct {
	NREncryption    string `json:"nr_encryption"`
	NRIntegrity     string `json:"nr_integrity"`
	EUTRAEncryption string `json:"eutra_encryption"`
	EUTRAIntegrity  string `json:"eutra_integrity"`
}

type PDUSessionSetupItemJSON struct {
	PDUSessionID              int64  `json:"pdu_session_id"`
	ULTeid                    uint32 `json:"ul_teid,omitempty"`
	TransportLayerAddress     string `json:"transport_layer_address,omitempty"`
	TransportLayerAddressIPv6 string `json:"transport_layer_address_ipv6,omitempty"`
}

type GlobalRANNodeIDJSON struct {
	Present     string           `json:"present"`
	GlobalGNBID *GlobalGNBIDJSON `json:"global_gnb_id,omitempty"`
}

type GlobalGNBIDJSON struct {
	PLMNIdentity   string `json:"plmn_identity"`
	GNBID          string `json:"gnb_id"`
	GNBIDBitLength int    `json:"gnb_id_bit_length,omitempty"`
}

type SupportedTAListJSON struct {
	Items []SupportedTAItemJSON `json:"items"`
}

type SupportedTAItemJSON struct {
	TAC            string                  `json:"tac"`
	BroadcastPLMNs []BroadcastPLMNItemJSON `json:"broadcast_plmns"`
}

type BroadcastPLMNItemJSON struct {
	PLMNIdentity string             `json:"plmn_identity"`
	SliceSupport []SliceSupportJSON `json:"slice_support"`
}

type SliceSupportJSON struct {
	SST string `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

type UserLocationInformationJSON struct {
	Present string                         `json:"present"`
	NR      *UserLocationInformationNRJSON `json:"nr,omitempty"`
}

type UserLocationInformationNRJSON struct {
	NRCGI NRCGIJSON `json:"nr_cgi"`
	TAI   TAIJSON   `json:"tai"`
}

type NRCGIJSON struct {
	PLMNIdentity   string `json:"plmn_identity"`
	NRCellIdentity string `json:"nr_cell_identity"`
}

type TAIJSON struct {
	PLMNIdentity string `json:"plmn_identity"`
	TAC          string `json:"tac"`
}

type FiveGSTMSIJSON struct {
	AMFSetID   string `json:"amf_set_id"`
	AMFPointer string `json:"amf_pointer"`
	FiveGTMSI  string `json:"five_g_tmsi"`
}

// Value indexes the ASN.1 enumeration of the named Cause CHOICE group (TS 38.413 §9.3.1.2).
type CauseJSON struct {
	Group string `json:"group"`
	Value int    `json:"value"`
}

type ServedGUAMIJSON struct {
	PLMNIdentity string `json:"plmn_identity"`
	AMFRegionID  string `json:"amf_region_id"`
	AMFSetID     string `json:"amf_set_id"`
	AMFPointer   string `json:"amf_pointer"`
}

type PLMNSupportJSON struct {
	PLMNIdentity string             `json:"plmn_identity"`
	SliceSupport []SliceSupportJSON `json:"slice_support"`
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

type AllowedNSSAIItemJSON struct {
	SST string `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

type MobilityRestrictionListJSON struct {
	ServingPLMN              string   `json:"serving_plmn"`
	EquivalentPLMNs          []string `json:"equivalent_plmns,omitempty"`
	RATRestrictions          []string `json:"rat_restrictions,omitempty"`
	ForbiddenAreaInformation []string `json:"forbidden_area_information,omitempty"`
	ServiceAreaInformation   []string `json:"service_area_information,omitempty"`
}

type UEAggregateMaxBitRateJSON struct {
	DL int64 `json:"dl"`
	UL int64 `json:"ul"`
}

type NGAPResponse struct {
	PDUType     string `json:"pdu_type"`
	MessageType string `json:"message_type"`
	RawHex      string `json:"raw_hex"`

	GlobalRANNodeID         *GlobalRANNodeIDJSON         `json:"global_ran_node_id,omitempty"`
	RANNodeName             *string                      `json:"ran_node_name,omitempty"`
	SupportedTAList         *SupportedTAListJSON         `json:"supported_ta_list,omitempty"`
	DefaultPagingDRX        *int64                       `json:"default_paging_drx,omitempty"`
	RANUENGAPID             *int64                       `json:"ran_ue_ngap_id,omitempty"`
	AMFUENGAPID             *int64                       `json:"amf_ue_ngap_id,omitempty"`
	NasPDU                  *string                      `json:"nas_pdu,omitempty"`
	UserLocationInformation *UserLocationInformationJSON `json:"user_location_information,omitempty"`
	RRCEstablishmentCause   *int64                       `json:"rrc_establishment_cause,omitempty"`
	FiveGSTMSI              *FiveGSTMSIJSON              `json:"five_g_s_tmsi,omitempty"`
	UEContextRequest        *int64                       `json:"ue_context_request,omitempty"`
	Cause                   *CauseJSON                   `json:"cause,omitempty"`
	AMFName                 *string                      `json:"amf_name,omitempty"`
	ServedGUAMIList         []ServedGUAMIJSON            `json:"served_guami_list,omitempty"`
	RelativeAMFCapacity     *int64                       `json:"relative_amf_capacity,omitempty"`
	PLMNSupportList         []PLMNSupportJSON            `json:"plmn_support_list,omitempty"`
	UERetentionInformation  *int64                       `json:"ue_retention_information,omitempty"`
	CriticalityDiagnostics  *CriticalityDiagnosticsJSON  `json:"criticality_diagnostics,omitempty"`
	TimeToWait              *string                      `json:"time_to_wait,omitempty"`

	AMFSetID             *string                `json:"amf_set_id_ie,omitempty"`
	AllowedNSSAI         []AllowedNSSAIItemJSON `json:"allowed_nssai,omitempty"`
	SelectedPLMNIdentity *string                `json:"selected_plmn_identity,omitempty"`

	OldAMF                  *string                      `json:"old_amf,omitempty"`
	RANPagingPriority       *int64                       `json:"ran_paging_priority,omitempty"`
	MobilityRestrictionList *MobilityRestrictionListJSON `json:"mobility_restriction_list,omitempty"`
	IndexToRFSP             *int64                       `json:"index_to_rfsp,omitempty"`
	UEAggregateMaxBitRate   *UEAggregateMaxBitRateJSON   `json:"ue_aggregate_max_bit_rate,omitempty"`

	UERadioCapability       *string                     `json:"ue_radio_capability,omitempty"`
	PDUSessionSetupItems    []PDUSessionSetupItemJSON   `json:"pdu_session_setup_items,omitempty"`
	PDUSessionIDs           []int64                     `json:"pdu_session_ids,omitempty"`
	ReleasePDUSessionIDs    []int64                     `json:"release_pdu_session_ids,omitempty"`
	NextHopChainingCount    *int64                      `json:"next_hop_chaining_count,omitempty"`
	NextHop                 *string                     `json:"next_hop,omitempty"`
	UESecurityCapabilities  *UESecurityCapabilitiesJSON `json:"ue_security_capabilities,omitempty"`
	RANStatusTransfer       *RANStatusTransferJSON      `json:"ran_status_transfer,omitempty"`
	SourceToTargetContainer *string                     `json:"source_to_target_transparent_container,omitempty"`

	ResetConnections []ResetConnectionJSON `json:"reset_connections,omitempty"`

	UnknownIEs []UnknownIEJSON `json:"unknown_ies,omitempty"`
}

type ResetConnectionJSON struct {
	AMFUENGAPID *int64 `json:"amf_ue_ngap_id,omitempty"`
	RANUENGAPID *int64 `json:"ran_ue_ngap_id,omitempty"`
}

type UnknownIEJSON struct {
	ID          int64  `json:"id"`
	Criticality string `json:"criticality"`
	ValueHex    string `json:"value_hex,omitempty"`
}
