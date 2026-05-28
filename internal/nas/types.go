package nas

// NASRequest is the JSON request for sending a NAS message via the /ngap endpoint.
// All optional IEs mirror TS 24.501 §8.2.6 (RegistrationRequest) 1:1.
// Any field present overrides the default/stored value.
type NASRequest struct {
	MessageType      string `json:"message_type"`
	RegistrationType *uint8 `json:"registration_type,omitempty"`

	// Raw NAS PDU override — when set, skip all NAS building and security
	// encoding. The hex bytes are stuffed directly into the NGAP wrapper.
	RawNASPDU *string `json:"raw_nas_pdu,omitempty"`

	// NGAP-level overrides (apply to the NGAP wrapper, not the NAS PDU)
	RRCEstablishmentCauseOverride *int64 `json:"rrc_establishment_cause,omitempty"`
	UEContextRequestOverride      *int64 `json:"ue_context_request,omitempty"`
	AmfUeNgapIDOverride           *int64 `json:"amf_ue_ngap_id_override,omitempty"`
	RanUeNgapIDOverride           *int64 `json:"ran_ue_ngap_id_override,omitempty"`

	// AuthenticationResponse override — replaces the computed RES*.
	ResStarOverride *string `json:"res_star_override,omitempty"`

	// PDU Session Establishment Request override — replaces the auto-built
	// inner SM payload that goes into the UL NAS Transport's payload container.
	// The outer UL NAS Transport, NAS security wrapping and NGAP encoding are
	// applied as usual. Used to exercise the AMF→SMF SM-payload error paths
	// without bypassing security.
	InnerSMPayload *string `json:"inner_sm_payload,omitempty"`

	// RegistrationRequest optional IEs (TS 24.501 §8.2.6)
	NgKSI                       *uint8  `json:"ng_ksi,omitempty"`
	MobileIdentityOverride      *string `json:"mobile_identity_override,omitempty"`
	NonCurrentNativeNASKSI      *uint8  `json:"non_current_native_nas_ksi,omitempty"`
	Capability5GMM              *string `json:"capability_5gmm,omitempty"`
	UESecurityCapabilityOverride *string `json:"ue_security_capability,omitempty"`
	RequestedNSSAI              []SNSSAIJSON `json:"requested_nssai,omitempty"`
	LastVisitedRegisteredTAI    *string `json:"last_visited_registered_tai,omitempty"`
	S1UENetworkCapability       *string `json:"s1_ue_network_capability,omitempty"`
	UplinkDataStatus            *string `json:"uplink_data_status,omitempty"`
	PDUSessionStatus            *string `json:"pdu_session_status,omitempty"`
	MICOIndication              *uint8  `json:"mico_indication,omitempty"`
	UEStatus                    *uint8  `json:"ue_status,omitempty"`
	AdditionalGUTI              *string `json:"additional_guti,omitempty"`
	AllowedPDUSessionStatus     *string `json:"allowed_pdu_session_status,omitempty"`
	UEsUsageSetting             *uint8  `json:"ues_usage_setting,omitempty"`
	RequestedDRXParameters      *uint8  `json:"requested_drx_parameters,omitempty"`
	EPSNASMessageContainer      *string `json:"eps_nas_message_container,omitempty"`
	LADNIndication              *string `json:"ladn_indication,omitempty"`
	PayloadContainerType        *uint8  `json:"payload_container_type,omitempty"`
	PayloadContainer            *string `json:"payload_container,omitempty"`
	NetworkSlicingIndication    *uint8  `json:"network_slicing_indication,omitempty"`
	UpdateType5GS               *string `json:"update_type_5gs,omitempty"`
	NASMessageContainer         *string `json:"nas_message_container,omitempty"`
	EPSBearerContextStatus      *string `json:"eps_bearer_context_status,omitempty"`
	RequestedExtendedDRX        *string `json:"requested_extended_drx,omitempty"`
	T3324Value                  *string `json:"t3324_value,omitempty"`
	UERadioCapabilityID         *string `json:"ue_radio_capability_id,omitempty"`
	RequestedMappedNSSAI        *string `json:"requested_mapped_nssai,omitempty"`
	AdditionalInfoRequested     *string `json:"additional_info_requested,omitempty"`
	RequestedWUSAssistance      *string `json:"requested_wus_assistance,omitempty"`
	N5GCIndication              *uint8  `json:"n5gc_indication,omitempty"`
	RequestedNBN1ModeDRX        *string `json:"requested_nb_n1_mode_drx,omitempty"`
	UERequestType               *string `json:"ue_request_type,omitempty"`
	PagingRestriction           *string `json:"paging_restriction,omitempty"`

	// Follow-On Request indicator (FOR bit)
	FollowOnRequest *uint8 `json:"follow_on_request,omitempty"`
}

type SNSSAIJSON struct {
	SST int32  `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

type NASResponse struct {
	MessageType        string `json:"message_type"`
	SecurityHeaderType string `json:"security_header_type,omitempty"`

	// AuthenticationRequest fields (TS 24.501 §8.2.1)
	RAND       string `json:"rand,omitempty"`
	AUTN       string `json:"autn,omitempty"`
	ABBAContents string `json:"abba,omitempty"`
	NgKSI      *uint8 `json:"ng_ksi,omitempty"`
	EAPMessage string `json:"eap_message,omitempty"`

	// SecurityModeCommand fields (TS 24.501 §8.2.25)
	SelectedCipheringAlg  *uint8 `json:"selected_ciphering_alg,omitempty"`
	SelectedIntegrityAlg  *uint8 `json:"selected_integrity_alg,omitempty"`

	// RegistrationAccept fields (TS 24.501 §8.2.7)
	GUTI string `json:"guti,omitempty"`

	// RegistrationReject / AuthenticationReject
	CauseGMM *uint8 `json:"cause_5gmm,omitempty"`

	// IdentityRequest
	IdentityType *uint8 `json:"identity_type,omitempty"`

	// PDU Session Establishment Accept (TS 24.501 §8.3.2)
	PDUSessionID   uint8  `json:"pdu_session_id,omitempty"`
	PDUSessionType uint8  `json:"pdu_session_type,omitempty"`
	PDUAddress     string `json:"pdu_address,omitempty"`

	// PDU Session Establishment Reject
	Cause5GSM *uint8 `json:"cause_5gsm,omitempty"`

	// DL NAS Transport inner message type
	InnerNASMessageType string `json:"inner_nas_message_type,omitempty"`

	// Raw hex of the NAS PDU
	RawHex string `json:"raw_hex,omitempty"`
}

const (
	RegistrationTypeInitial   uint8 = 1
	RegistrationTypeMobility  uint8 = 2
	RegistrationTypePeriodic  uint8 = 3
	RegistrationTypeEmergency uint8 = 4
)
