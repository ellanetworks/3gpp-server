// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas

type SNSSAIJSON struct {
	SST int32  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

// GUTI5GJSON is the decoded 5G-GUTI (TS 24.501 §9.11.3.4). The AMF Region ID /
// Set ID / Pointer fields are 5G-specific; the 4G analogue is naseps.GUTIJSON.
type GUTI5GJSON struct {
	MCC         string `json:"mcc"`
	MNC         string `json:"mnc"`
	AMFRegionID int    `json:"amf_region_id"`
	AMFSetID    int    `json:"amf_set_id"`
	AMFPointer  int    `json:"amf_pointer"`
	FiveGTMSI   string `json:"5g_tmsi"`
}

type NASResponse struct {
	MessageType        string `json:"message_type"`
	SecurityHeaderType string `json:"security_header_type,omitempty"`

	RAND         string `json:"rand,omitempty"`
	AUTN         string `json:"autn,omitempty"`
	ABBAContents string `json:"abba,omitempty"`
	NgKSI        *int   `json:"ng_ksi,omitempty"`
	EAPMessage   string `json:"eap_message,omitempty"`

	SelectedCipheringAlgorithm *int `json:"selected_ciphering_algorithm,omitempty"`
	SelectedIntegrityAlgorithm *int `json:"selected_integrity_algorithm,omitempty"`
	IMEISVRequested            bool `json:"imeisv_requested,omitempty"`

	GUTI    *GUTI5GJSON `json:"guti,omitempty"`
	TAIList string      `json:"tai_list,omitempty"`

	PDUSessionStatus string `json:"pdu_session_status,omitempty"`

	// The numeric IEs below are pointers so a decoded value of 0 stays distinct from an absent IE under omitempty.
	PDUSessionID   *int   `json:"pdu_session_id,omitempty"`
	PDUSessionType *int   `json:"pdu_session_type,omitempty"`
	SSCMode        *int   `json:"ssc_mode,omitempty"`
	PDUAddress     string `json:"pdu_address,omitempty"`
	PTI            *int   `json:"pti,omitempty"`

	AccessTypePresent *bool `json:"access_type_present,omitempty"`

	SessionAMBRUplink   *int   `json:"session_ambr_uplink,omitempty"`
	SessionAMBRDownlink *int   `json:"session_ambr_downlink,omitempty"`
	AuthorizedQoSRules  string `json:"authorized_qos_rules,omitempty"`
	AlwaysOnIndication  *int   `json:"always_on_indication,omitempty"`

	FiveGMMCause *int `json:"5gmm_cause,omitempty"`
	FiveGSMCause *int `json:"5gsm_cause,omitempty"`

	IdentityType *int `json:"identity_type,omitempty"`

	InnerNASMessageType string `json:"inner_nas_message_type,omitempty"`

	RawHex string `json:"raw_hex"`
}

const (
	RegistrationTypeInitial   uint8 = 1
	RegistrationTypeMobility  uint8 = 2
	RegistrationTypePeriodic  uint8 = 3
	RegistrationTypeEmergency uint8 = 4
)
