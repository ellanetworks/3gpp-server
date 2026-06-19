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

	// ERABSetupItems lists the E-RABs an Initial Context Setup Request asks the
	// eNB to set up (the default bearer carries the Attach Accept NAS).
	ERABSetupItems []ERABSetupItemJSON `json:"erab_setup_items,omitempty"`

	// UERadioCapability is the UE radio capability the MME replays in an Initial
	// Context Setup Request (hex), when present (TS 23.401 §5.11.2).
	UERadioCapability *string `json:"ue_radio_capability,omitempty"`

	// Cause is set on an Error Indication (TS 36.413 §9.1.4.3) and a Path Switch
	// Request Failure (§9.1.5.10).
	Cause *CauseJSON `json:"cause,omitempty"`

	// SecurityContext is set on a Path Switch Request Acknowledge: the {NCC, NH}
	// the target eNB uses to derive the next K_eNB (TS 33.401 §7.2.8).
	SecurityContext *SecurityContextJSON `json:"security_context,omitempty"`

	// ResetConnections is set on a Reset Acknowledge: the UE-associated logical S1
	// connections the MME reset, echoed for a partial reset (TS 36.413 §8.7.1.2.1).
	ResetConnections []ResetConnectionJSON `json:"reset_connections,omitempty"`

	// ReplayedUESecurityCapabilities is set on a Path Switch Request Acknowledge
	// only when the MME's stored UE security capabilities differ from those the
	// target eNB reported, so the eNB corrects its context (TS 36.413 §9.1.5.9).
	ReplayedUESecurityCapabilities *UESecurityCapabilitiesJSON `json:"replayed_ue_security_capabilities,omitempty"`
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

// ERABSetupItemJSON identifies an E-RAB the MME asked the eNB to set up, with the
// S-GW S1-U endpoint the eNB sends uplink user data to.
type ERABSetupItemJSON struct {
	ERABID                int    `json:"erab_id"`
	GTPTEID               uint32 `json:"gtp_teid,omitempty"`
	TransportLayerAddress string `json:"transport_layer_address,omitempty"`
}

type S1SetupResponseJSON struct {
	MMEName             string             `json:"mme_name,omitempty"`
	ServedGUMMEIs       []ServedGUMMEIJSON `json:"served_gummeis"`
	RelativeMMECapacity int                `json:"relative_mme_capacity"`
}

// ServedGUMMEIJSON renders the PLMNs, MME group IDs, and MME codes of one served
// GUMMEI item as hex octet strings, matching the PLMN encoding used elsewhere.
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

// ResetConnectionJSON is one UE-associated logical S1 connection in a Reset
// Acknowledge connection list (TS 36.413 §9.2.3.20).
type ResetConnectionJSON struct {
	MMEUES1APID *int64 `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID *int64 `json:"enb_ue_s1ap_id,omitempty"`
}
