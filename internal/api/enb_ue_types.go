// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
)

type CreateENBUERequest struct {
	IMSI                string `json:"imsi"`
	IMEISV              string `json:"imeisv,omitempty"`
	K                   string `json:"k"`
	OPc                 string `json:"opc"`
	AMF                 string `json:"amf,omitempty"`
	SQN                 string `json:"sqn,omitempty"`
	UENetworkCapability string `json:"ue_network_capability,omitempty"`
}

type CreateENBUEResponse struct {
	UEID        string `json:"ue_id"`
	IMSI        string `json:"imsi"`
	ENBUES1APID uint32 `json:"enb_ue_s1ap_id"`
}

type SendENBUES1APRequest struct {
	MessageType string `json:"message_type"`

	PDNType     uint8 `json:"pdn_type,omitempty"`
	AttachType  uint8 `json:"attach_type,omitempty"`
	ForeignGUTI bool  `json:"foreign_guti,omitempty"`

	UENetworkCapabilityOverride     *string `json:"ue_network_capability,omitempty"`
	OldPTMSISignature               *string `json:"old_ptmsi_signature,omitempty"`
	AdditionalGUTI                  *string `json:"additional_guti,omitempty"`
	LastVisitedRegisteredTAI        *string `json:"last_visited_registered_tai,omitempty"`
	DRXParameter                    *string `json:"drx_parameter,omitempty"`
	MSNetworkCapability             *string `json:"ms_network_capability,omitempty"`
	OldLocationAreaID               *string `json:"old_location_area_identification,omitempty"`
	TMSIStatus                      *uint8  `json:"tmsi_status,omitempty"`
	MobileStationClassmark2         *string `json:"mobile_station_classmark_2,omitempty"`
	MobileStationClassmark3         *string `json:"mobile_station_classmark_3,omitempty"`
	SupportedCodecs                 *string `json:"supported_codecs,omitempty"`
	AdditionalUpdateType            *uint8  `json:"additional_update_type,omitempty"`
	VoiceDomainPreference           *string `json:"voice_domain_preference,omitempty"`
	DeviceProperties                *uint8  `json:"device_properties,omitempty"`
	OldGUTIType                     *uint8  `json:"old_guti_type,omitempty"`
	MSNetworkFeatureSupport         *uint8  `json:"ms_network_feature_support,omitempty"`
	TMSIBasedNRIContainer           *string `json:"tmsi_based_nri_container,omitempty"`
	T3324Value                      *string `json:"t3324_value,omitempty"`
	T3412ExtendedValue              *string `json:"t3412_extended_value,omitempty"`
	ExtendedDRXParameters           *string `json:"extended_drx_parameters,omitempty"`
	UEAdditionalSecurityCapability  *string `json:"ue_additional_security_capability,omitempty"`
	UEStatus                        *string `json:"ue_status,omitempty"`
	AdditionalInformationRequested  *string `json:"additional_information_requested,omitempty"`
	N1UENetworkCapability           *string `json:"n1_ue_network_capability,omitempty"`
	UERadioCapabilityIDAvailability *string `json:"ue_radio_capability_id_availability,omitempty"`
	RequestedWUSAssistance          *string `json:"requested_wus_assistance_information,omitempty"`
	DRXParameterNBS1Mode            *string `json:"drx_parameter_nb_s1_mode,omitempty"`
	RequestedIMSIOffset             *string `json:"requested_imsi_offset,omitempty"`

	RawNASPDU  *string `json:"raw_nas_pdu,omitempty"`
	CorruptMAC bool    `json:"corrupt_mac,omitempty"`

	MMEUES1APIDOverride           *uint32 `json:"mme_ue_s1ap_id_override,omitempty"`
	ENBUES1APIDOverride           *uint32 `json:"enb_ue_s1ap_id_override,omitempty"`
	RRCEstablishmentCauseOverride *int64  `json:"rrc_establishment_cause,omitempty"`

	ReplayLast        bool    `json:"replay_last,omitempty"`
	SwitchOff         bool    `json:"switch_off,omitempty"`
	ReleaseCause      *int64  `json:"release_cause,omitempty"`
	UERadioCapability *string `json:"ue_radio_capability,omitempty"`
	MTMSIOverride     *uint32 `json:"mtmsi,omitempty"`
	NASCountOverride  *uint32 `json:"nas_count,omitempty"`
	EPSUpdateType     uint8   `json:"eps_update_type,omitempty"`

	APN               string `json:"apn,omitempty"`
	PTI               *uint8 `json:"pti,omitempty"`
	RequestEBI        *uint8 `json:"request_ebi,omitempty"`
	LinkedEBI         *uint8 `json:"linked_ebi,omitempty"`
	EPSBearerIdentity *uint8 `json:"eps_bearer_identity,omitempty"`
	ESMCause          *uint8 `json:"esm_cause,omitempty"`
	WithholdAccept    bool   `json:"withhold_accept,omitempty"`

	RESOverride *string `json:"res_override,omitempty"`
	Cause       *int64  `json:"cause,omitempty"`

	TargetENBID             *string `json:"target_enb_id,omitempty"`
	HandoverRequiredCause   *int64  `json:"handover_required_cause,omitempty"`
	HandoverCancelCause     *int64  `json:"handover_cancel_cause,omitempty"`
	StatusTransferContainer *string `json:"status_transfer_container,omitempty"`

	TimeoutMs int `json:"timeout_ms,omitempty"`
}

type HandoverERAB struct {
	ID     uint8  `json:"id"`
	DLTeid uint32 `json:"dl_teid,omitempty"`
	DLIP   string `json:"dl_ip,omitempty"`
}

type MigrateENBUERequest struct {
	TargetENBID string  `json:"target_enb_id"`
	MMEUES1APID *uint32 `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID *uint32 `json:"enb_ue_s1ap_id,omitempty"`
}

type ENBUEBearer struct {
	EBI  uint8  `json:"ebi"`
	APN  string `json:"apn"`
	UEIP string `json:"ue_ip"`
}

type ENBUEStateResponse struct {
	UEID           string        `json:"ue_id"`
	IMSI           string        `json:"imsi"`
	IMEISV         string        `json:"imeisv,omitempty"`
	UEIP           string        `json:"ue_ip"`
	SecurityActive bool          `json:"security_active"`
	MMEUES1APID    uint32        `json:"mme_ue_s1ap_id"`
	ENBUES1APID    uint32        `json:"enb_ue_s1ap_id"`
	DefaultEBI     uint8         `json:"default_ebi"`
	Bearers        []ENBUEBearer `json:"bearers"`
}

type MigrateENBUEResponse struct {
	UEID        string `json:"ue_id"`
	ENBID       string `json:"enb_id"`
	MMEUES1APID uint32 `json:"mme_ue_s1ap_id"`
	ENBUES1APID uint32 `json:"enb_ue_s1ap_id"`
}

type SendENBUES1APResponse struct {
	S1AP        *s1ap.S1APResponse  `json:"s1ap,omitempty"`
	NAS         *naseps.NASResponse `json:"nas,omitempty"`
	MACVerified *bool               `json:"mac_verified,omitempty"`
}
