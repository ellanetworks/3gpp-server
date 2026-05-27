package ngap

import "encoding/json"

type NGAPMessage struct {
	ProcedureCode int64           `json:"procedure_code"`
	PDUType       string          `json:"pdu_type"`
	Criticality   string          `json:"criticality"`
	IEs           []IE            `json:"ies,omitempty"`
	RawPDU        string          `json:"raw_pdu,omitempty"`
}

type IE struct {
	ID          int64           `json:"id"`
	Criticality string          `json:"criticality,omitempty"`
	Value       json.RawMessage `json:"value,omitempty"`

	// Typed fields — at most one is set per IE. The encode layer
	// checks these first; if none match, it falls back to Value.
	GlobalRANNodeID          *GlobalRANNodeIDJSON          `json:"global_ran_node_id,omitempty"`
	RANNodeName              *string                       `json:"ran_node_name,omitempty"`
	SupportedTAList          *SupportedTAListJSON          `json:"supported_ta_list,omitempty"`
	DefaultPagingDRX         *int64                        `json:"default_paging_drx,omitempty"`
	RanUeNgapID              *int64                        `json:"ran_ue_ngap_id,omitempty"`
	AmfUeNgapID              *int64                        `json:"amf_ue_ngap_id,omitempty"`
	NasPDU                   *string                       `json:"nas_pdu,omitempty"`
	UserLocationInformation  *UserLocationInformationJSON  `json:"user_location_information,omitempty"`
	RRCEstablishmentCause    *int64                        `json:"rrc_establishment_cause,omitempty"`
	FiveGSTMSI               *FiveGSTMSIJSON               `json:"five_g_s_tmsi,omitempty"`
	UEContextRequest         *int64                        `json:"ue_context_request,omitempty"`
	Cause                    *CauseJSON                    `json:"cause,omitempty"`
	AMFName                  *string                       `json:"amf_name,omitempty"`
	ServedGUAMIList          []ServedGUAMIJSON             `json:"served_guami_list,omitempty"`
	RelativeAMFCapacity      *int64                        `json:"relative_amf_capacity,omitempty"`
	PLMNSupportList          []PLMNSupportJSON             `json:"plmn_support_list,omitempty"`
	UERetentionInformation   *int64                        `json:"ue_retention_information,omitempty"`
	CriticalityDiagnostics   *CriticalityDiagnosticsJSON   `json:"criticality_diagnostics,omitempty"`
	TimeToWait               *int64                        `json:"time_to_wait,omitempty"`
}

type GlobalRANNodeIDJSON struct {
	Present    string `json:"present"`
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
	TAC              string                   `json:"tac"`
	BroadcastPLMNs   []BroadcastPLMNItemJSON  `json:"broadcast_plmns"`
}

type BroadcastPLMNItemJSON struct {
	PLMNIdentity    string          `json:"plmn_identity"`
	SliceSupport    []SliceSupportJSON `json:"slice_support"`
}

type SliceSupportJSON struct {
	SST string `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

type UserLocationInformationJSON struct {
	Present string                          `json:"present"`
	NR      *UserLocationInformationNRJSON  `json:"nr,omitempty"`
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
	ProcedureCode      *int64                        `json:"procedure_code,omitempty"`
	TriggeringMessage  *string                       `json:"triggering_message,omitempty"`
	ProcedureCriticality *string                     `json:"procedure_criticality,omitempty"`
	IEsCriticalityDiagnostics []IECriticalityDiagnosticJSON `json:"ies_criticality_diagnostics,omitempty"`
}

type IECriticalityDiagnosticJSON struct {
	IECriticality string `json:"ie_criticality"`
	IEID          int64  `json:"ie_id"`
	TypeOfError   string `json:"type_of_error"`
}

type NGAPResponse struct {
	PDUType     string `json:"pdu_type"`
	MessageType string `json:"message_type"`
	RawHex      string `json:"raw_hex"`

	IEs []IE `json:"ies,omitempty"`
}
