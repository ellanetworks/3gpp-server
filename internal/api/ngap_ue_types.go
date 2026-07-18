// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	nasTypes "github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
)

type SendNGAPRequest struct {
	MessageType      string `json:"message_type"`
	RegistrationType *uint8 `json:"registration_type,omitempty"`

	// RawNASPDU bypasses NAS building and security encoding entirely; the hex bytes go straight into the NGAP wrapper.
	RawNASPDU *string `json:"raw_nas_pdu,omitempty"`

	RRCEstablishmentCauseOverride *int64 `json:"rrc_establishment_cause,omitempty"`
	UEContextRequestOverride      *int64 `json:"ue_context_request,omitempty"`
	AMFUENGAPIDOverride           *int64 `json:"amf_ue_ngap_id_override,omitempty"`
	RANUENGAPIDOverride           *int64 `json:"ran_ue_ngap_id_override,omitempty"`

	ResStarOverride *string `json:"res_star_override,omitempty"`

	InnerSMPayload *string `json:"inner_sm_payload,omitempty"`

	ReleaseCause *int64 `json:"release_cause,omitempty"`

	DeregSwitchOff *uint8 `json:"switch_off,omitempty"`

	ServiceType *uint8 `json:"service_type,omitempty"`

	RequestTypeOverride *uint8 `json:"request_type,omitempty"`

	PTIOverride *uint8 `json:"pti,omitempty"`

	AlwaysOnRequested *bool `json:"always_on_requested,omitempty"`

	FiveGSMCauseOverride *uint8 `json:"5gsm_cause,omitempty"`

	NgKSI                        *uint8                `json:"ng_ksi,omitempty"`
	MobileIdentityOverride       *string               `json:"mobile_identity_override,omitempty"`
	NonCurrentNativeNASKSI       *uint8                `json:"non_current_native_nas_ksi,omitempty"`
	Capability5GMM               *string               `json:"capability_5gmm,omitempty"`
	UESecurityCapabilityOverride *string               `json:"ue_security_capability,omitempty"`
	RequestedNSSAI               []nasTypes.SNSSAIJSON `json:"requested_nssai,omitempty"`
	LastVisitedRegisteredTAI     *string               `json:"last_visited_registered_tai,omitempty"`
	S1UENetworkCapability        *string               `json:"s1_ue_network_capability,omitempty"`
	UplinkDataStatus             *string               `json:"uplink_data_status,omitempty"`
	PDUSessionStatus             *string               `json:"pdu_session_status,omitempty"`
	MICOIndication               *uint8                `json:"mico_indication,omitempty"`
	UEStatus                     *uint8                `json:"ue_status,omitempty"`
	AdditionalGUTI               *string               `json:"additional_guti,omitempty"`
	AllowedPDUSessionStatus      *string               `json:"allowed_pdu_session_status,omitempty"`
	UEsUsageSetting              *uint8                `json:"ues_usage_setting,omitempty"`
	RequestedDRXParameters       *uint8                `json:"requested_drx_parameters,omitempty"`
	EPSNASMessageContainer       *string               `json:"eps_nas_message_container,omitempty"`
	LADNIndication               *string               `json:"ladn_indication,omitempty"`
	PayloadContainer             *string               `json:"payload_container,omitempty"`
	NetworkSlicingIndication     *uint8                `json:"network_slicing_indication,omitempty"`
	UpdateType5GS                *string               `json:"update_type_5gs,omitempty"`
	NASMessageContainer          *string               `json:"nas_message_container,omitempty"`
	EPSBearerContextStatus       *string               `json:"eps_bearer_context_status,omitempty"`

	FollowOnRequest *uint8 `json:"follow_on_request,omitempty"`

	FiveGMMCause *uint8 `json:"5gmm_cause,omitempty"`

	TargetGnbID *string `json:"target_gnb_id,omitempty"`

	PDUSessionIDs []int64 `json:"pdu_session_ids,omitempty"`

	HandoverCancelCause *int64 `json:"handover_cancel_cause,omitempty"`

	HandoverRequiredCause *int64 `json:"handover_required_cause,omitempty"`

	StatusTransferDRBs []DRBStatusTransferInput `json:"status_transfer_drbs,omitempty"`

	PDUSessionIDOverride *uint8 `json:"pdu_session_id,omitempty"`

	ExistingConnection bool `json:"existing_connection,omitempty"`

	CorruptMAC bool `json:"corrupt_mac,omitempty"`

	NASCountOverride *uint32 `json:"nas_count,omitempty"`

	ReplayLast bool `json:"replay_last,omitempty"`

	TimeoutMs int `json:"timeout_ms,omitempty"`

	UERadioCapability *string `json:"ue_radio_capability,omitempty"`
}

type DRBStatusTransferInput struct {
	DRBID    int64 `json:"drb_id"`
	ULPDCPSN int64 `json:"ul_pdcp_sn,omitempty"`
	ULHFN    int64 `json:"ul_hfn,omitempty"`
	DLPDCPSN int64 `json:"dl_pdcp_sn,omitempty"`
	DLHFN    int64 `json:"dl_hfn,omitempty"`
}

type SendNGAPResponse struct {
	NGAP        *ngap.NGAPResponse    `json:"ngap,omitempty"`
	NAS         *nasTypes.NASResponse `json:"nas,omitempty"`
	MACVerified *bool                 `json:"mac_verified,omitempty"`
}
