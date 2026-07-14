// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import "encoding/json"

type NGAPMessage struct {
	ProcedureCode int64  `json:"procedure_code"`
	PDUType       string `json:"pdu_type"`
	Criticality   string `json:"criticality"`
	IEs           []IE   `json:"ies,omitempty"`
	RawPDU        string `json:"raw_pdu,omitempty"`
}

type IE struct {
	ID          int64           `json:"id"`
	Criticality string          `json:"criticality,omitempty"`
	Value       json.RawMessage `json:"value,omitempty"`

	// Typed fields — at most one is set per IE. The encode layer
	// checks these first; if none match, it falls back to Value.
	GlobalRANNodeID         *GlobalRANNodeIDJSON         `json:"global_ran_node_id,omitempty"`
	RANNodeName             *string                      `json:"ran_node_name,omitempty"`
	SupportedTAList         *SupportedTAListJSON         `json:"supported_ta_list,omitempty"`
	DefaultPagingDRX        *int64                       `json:"default_paging_drx,omitempty"`
	RanUeNgapID             *int64                       `json:"ran_ue_ngap_id,omitempty"`
	AmfUeNgapID             *int64                       `json:"amf_ue_ngap_id,omitempty"`
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

	// InitialUEMessage optional IEs (TS 38.413 §9.2.5.1)
	AMFSetID             *string                `json:"amf_set_id_ie,omitempty"`
	AllowedNSSAI         []AllowedNSSAIItemJSON `json:"allowed_nssai,omitempty"`
	SelectedPLMNIdentity *string                `json:"selected_plmn_identity,omitempty"`

	// DownlinkNASTransport optional IEs (TS 38.413 §9.2.5.2)
	OldAMF                  *string                      `json:"old_amf,omitempty"`
	RANPagingPriority       *int64                       `json:"ran_paging_priority,omitempty"`
	MobilityRestrictionList *MobilityRestrictionListJSON `json:"mobility_restriction_list,omitempty"`
	IndexToRFSP             *int64                       `json:"index_to_rfsp,omitempty"`
	UEAggregateMaxBitRate   *UEAggregateMaxBitRateJSON   `json:"ue_aggregate_max_bit_rate,omitempty"`

	// UERadioCapability is the UE radio capability the AMF replays in an Initial
	// Context Setup Request (hex, TS 38.413 §9.3.1.74).
	UERadioCapability *string `json:"ue_radio_capability,omitempty"`

	// PDUSessionSetupItems surface, per session in a PDU Session Resource Setup
	// Request, the UPF's uplink GTP-U tunnel (decoded from the per-session
	// transfer) so the emulated gNB can terminate the N3 data path.
	PDUSessionSetupItems []PDUSessionSetupItemJSON `json:"pdu_session_setup_items,omitempty"`

	// PDU session IDs carried by a handover PDU-session list (e.g. the setup
	// list in a Handover Request, the handover list in a Handover Command).
	PDUSessionIDs []int64 `json:"pdu_session_ids,omitempty"`

	// ReleasePDUSessionIDs are the PDU sessions a Handover Command tells the
	// source to release (those the target did not admit).
	ReleasePDUSessionIDs []int64 `json:"release_pdu_session_ids,omitempty"`

	// NextHopChainingCount from a Handover Request's Security Context IE; its
	// presence confirms the AMF passed the security context to the target.
	NextHopChainingCount *int64 `json:"next_hop_chaining_count,omitempty"`

	// UESecurityCapabilities from a Path Switch Request Acknowledge: the AMF's
	// locally stored UE 5G security capabilities, returned on a mismatch with the
	// values the target gNB reported (TS 33.501 §6.7.3.1).
	UESecurityCapabilities *UESecurityCapabilitiesJSON `json:"ue_security_capabilities,omitempty"`
}

// UESecurityCapabilitiesJSON holds the NR/E-UTRA encryption and integrity
// algorithm bitmaps of a UE Security Capabilities IE (TS 38.413 §9.3.1.86), each
// as a hex-encoded big-endian bitmap.
type UESecurityCapabilitiesJSON struct {
	NREncryption    string `json:"nr_encryption"`
	NRIntegrity     string `json:"nr_integrity"`
	EUTRAEncryption string `json:"eutra_encryption"`
	EUTRAIntegrity  string `json:"eutra_integrity"`
}

// PDUSessionSetupItemJSON is one session in a PDU Session Resource Setup
// Request, with the UPF's uplink N3 GTP-U tunnel.
type PDUSessionSetupItemJSON struct {
	PDUSessionID int64  `json:"pdu_session_id"`
	ULTeid       uint32 `json:"ul_teid,omitempty"`
	UPFN3IP      string `json:"upf_n3_ip,omitempty"`
	UPFN3IPv6    string `json:"upf_n3_ipv6,omitempty"`
}

type GlobalRANNodeIDJSON struct {
	Present     string           `json:"present"`
	GlobalGNBID *GlobalGNBIDJSON `json:"global_gnb_id,omitempty"`
}

type GlobalGNBIDJSON struct {
	PLMNIdentity string `json:"plmn_identity"`
	GnbID        string `json:"gnb_id"`
	GnbIDBitLen  int    `json:"gnb_id_bit_length,omitempty"`
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

type CauseJSON struct {
	Present      string `json:"present"`
	RadioNetwork *int64 `json:"radio_network,omitempty"`
	Transport    *int64 `json:"transport,omitempty"`
	NAS          *int64 `json:"nas,omitempty"`
	Protocol     *int64 `json:"protocol,omitempty"`
	Misc         *int64 `json:"misc,omitempty"`
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

	IEs []IE `json:"ies,omitempty"`
}
