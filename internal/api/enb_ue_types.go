// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
)

type CreateENBUERequest struct {
	IMSI string `json:"imsi"`
	K    string `json:"k"`
	OPc  string `json:"opc"`
	AMF  string `json:"amf,omitempty"`
	SQN  string `json:"sqn,omitempty"`

	// UENetworkCapability overrides the advertised EEA/EIA support bitmap (hex),
	// e.g. "2020" for EEA2/EIA2 only. Defaults to EEA0/1/2 + EIA0/1/2.
	UENetworkCapability string `json:"ue_network_capability,omitempty"`
}

type CreateENBUEResponse struct {
	UEID        string `json:"ue_id"`
	ENBUES1APID uint32 `json:"enb_ue_s1ap_id"`
}

// SendENBNASRequest drives one step of an EPS procedure from the emulated UE.
// message_type selects the uplink message; the response carries the MME's reply.
type SendENBNASRequest struct {
	MessageType string `json:"message_type"`

	// PDNType selects the requested PDN type for the attach (default IPv4).
	PDNType uint8 `json:"pdn_type,omitempty"`

	// AttachType selects the EPS attach type (1=EPS, 2=combined EPS/IMSI,
	// 6=emergency); default EPS.
	AttachType uint8 `json:"attach_type,omitempty"`

	// ForeignGUTI makes attach_request use a GUTI mobile identity the MME does not
	// know (instead of the IMSI), to drive the Identity procedure (§5.4.4).
	ForeignGUTI bool `json:"foreign_guti,omitempty"`

	// RawNASPDU, on attach_request, sends these hex bytes verbatim as the Initial
	// UE Message's NAS PDU in place of a built Attach Request — for malformed-NAS
	// robustness tests. A reply that times out yields a null response, not an error.
	RawNASPDU *string `json:"raw_nas_pdu,omitempty"`

	// CorruptMAC, on security_mode_complete, flips a byte of the NAS-MAC so the
	// MME's integrity check fails; the MME must discard the message (§4.4.4).
	CorruptMAC bool `json:"corrupt_mac,omitempty"`

	// MMEUES1APIDOverride, on inject_nas, sets the MME-UE-S1AP-ID of the Uplink NAS
	// Transport to an arbitrary value (e.g. another UE's, or one never assigned),
	// to test the MME's UE-association validation (TS 36.413 §10.6).
	MMEUES1APIDOverride *uint32 `json:"mme_ue_s1ap_id,omitempty"`

	// ENBUES1APIDOverride, on inject_nas, sets the eNB-UE-S1AP-ID of the Uplink NAS
	// Transport, so a valid MME-UE-S1AP-ID can be paired with an inconsistent
	// eNB-UE-S1AP-ID to test the MME's AP-ID pair validation (TS 36.413 §10.6).
	ENBUES1APIDOverride *uint32 `json:"enb_ue_s1ap_id,omitempty"`

	// ReplayLast, on inject_nas, resends this UE's last uplink NAS PDU verbatim, to
	// test NAS replay protection (TS 24.301 §4.4.3.5).
	ReplayLast bool `json:"replay_last,omitempty"`

	// SwitchOff, on detach_request, marks the UE as powering off — the network
	// does not send a Detach Accept (TS 24.301 §5.5.2.2.2).
	SwitchOff bool `json:"switch_off,omitempty"`

	// ReleaseCause, on release_request, is the radio-network Cause value the eNB
	// reports in the UE Context Release Request (TS 36.413 §9.2.1.3); the MME
	// echoes it in the Release Command. Defaults to user-inactivity (20).
	ReleaseCause *int `json:"release_cause,omitempty"`

	// ResetAll, on reset, resets the whole S1 interface (s1-Interface reset-all)
	// rather than only this UE's connection (partOfS1-Interface) — TS 36.413 §8.7.1.
	ResetAll bool `json:"reset_all,omitempty"`

	// UERadioCapability, on ue_capability_info, is the hex radio capability the eNB
	// reports; the MME should replay it in a later Initial Context Setup Request.
	UERadioCapability string `json:"ue_radio_capability,omitempty"`

	// MTMSIOverride, on service_request, sets the S-TMSI's M-TMSI to an arbitrary
	// value (e.g. one the MME never assigned) for unknown-UE tests.
	MTMSIOverride *uint32 `json:"mtmsi,omitempty"`

	// NASCountOverride, on service_request and tracking_area_update, forces the
	// uplink NAS COUNT (e.g. a stale value) for replay tests.
	NASCountOverride *uint32 `json:"nas_count,omitempty"`

	// EPSUpdateType, on tracking_area_update, selects the TAU type: 0=TA, 1/2=
	// combined TA/LA, 3=periodic (TS 24.301 §9.9.3.14).
	EPSUpdateType uint8 `json:"eps_update_type,omitempty"`

	// PathSwitchERABID, on path_switch, overrides the E-RAB ID in the
	// to-be-switched list — set to an unestablished E-RAB to drive the
	// no-bearer-switched failure (TS 36.413).
	PathSwitchERABID *uint8 `json:"path_switch_erab_id,omitempty"`

	// DuplicateERAB, on path_switch, lists the E-RAB ID twice, an abnormal
	// condition the MME rejects with cause multiple-E-RAB-ID-instances.
	DuplicateERAB bool `json:"duplicate_erab,omitempty"`

	// PathSwitchEEA / PathSwitchEIA, on path_switch, override the UE security
	// capability bitmaps the target eNB reports (TS 36.413 §9.2.1.40). When they
	// differ from the MME's stored values, the MME replays the stored caps in the
	// Acknowledge (TS 36.413 §9.1.5.9).
	PathSwitchEEA *uint16 `json:"path_switch_eea,omitempty"`
	PathSwitchEIA *uint16 `json:"path_switch_eia,omitempty"`

	// APN, on pdn_connectivity, is the access point name of the additional PDN
	// connection to establish (TS 24.301 §6.5.1). Empty requests the default APN.
	APN string `json:"apn,omitempty"`

	// PTI overrides the procedure transaction identity on pdn_connectivity /
	// pdn_disconnect — set to 0 (reserved) to drive the §7.3.1 invalid-PTI handling.
	PTI *uint8 `json:"pti,omitempty"`

	// RequestEBI overrides the ESM-header EPS bearer identity on a PDN Connectivity
	// Request (normally 0) — a non-zero value drives the §7.3.2 invalid-EBI handling.
	RequestEBI *uint8 `json:"request_ebi,omitempty"`

	// LinkedEBI, on pdn_disconnect, is the linked default-bearer identity of the
	// PDN connection to release (TS 24.301 §6.5.2). Defaults to the default bearer.
	LinkedEBI *uint8 `json:"linked_ebi,omitempty"`

	// RESOverride, when set, replaces the computed RES with these hex bytes —
	// for the wrong-RES authentication tests.
	RESOverride *string `json:"res_override,omitempty"`

	// Cause is the EMM cause for an authentication_failure step (TS 24.301
	// §5.4.2.6): #20 MAC failure, #21 synch failure (AUTS auto-included), #26
	// non-EPS authentication unacceptable.
	Cause *int `json:"cause,omitempty"`

	// TargetENBID, on handover_required, is the store ID of the eNB to hand the UE
	// over to; its PLMN and eNB-ID form the Target eNB-ID the MME resolves.
	TargetENBID *string `json:"target_enb_id,omitempty"`

	// HandoverCause overrides the radio-network Cause on a handover_required
	// (default handover-desirable-for-radio-reasons) or handover_cancel (default
	// handover-cancelled), TS 36.413 §9.2.1.3.
	HandoverCause *int `json:"handover_cause,omitempty"`

	// StatusTransferContainer, on enb_status_transfer, is the opaque PDCP status
	// container (hex) relayed to the target eNB (TS 36.413 §9.1.5.7).
	StatusTransferContainer *string `json:"status_transfer_container,omitempty"`

	TimeoutMs int `json:"timeout_ms,omitempty"`
}

// SendENBS1APRequest drives a non-UE-associated S1AP message on the eNB's S1-MME
// association — the target-eNB side of S1 handover. The S1AP ID pair addresses a
// UE the target eNB does not own; the MME assigned the MME UE S1AP ID and the
// eNB chooses its own eNB UE S1AP ID.
type SendENBS1APRequest struct {
	MessageType string `json:"message_type"`

	MMEUES1APID *uint32 `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID *uint32 `json:"enb_ue_s1ap_id,omitempty"`

	// Admitted lists the E-RABs the target eNB accepts in a
	// handover_request_acknowledge; FailedERABs lists those it rejects.
	Admitted    []HandoverERAB `json:"admitted_erabs,omitempty"`
	FailedERABs []uint8        `json:"failed_erabs,omitempty"`

	// Cause overrides the radio-network Cause on a handover_failure (default
	// ho-failure-in-target-EPC-eNB-or-target-system), TS 36.413 §9.2.1.3.
	Cause *int `json:"cause,omitempty"`

	// CellID overrides the E-UTRAN cell identity a handover_notify reports as the
	// UE's new location (TS 36.413 §9.2.1.38). Defaults to 1.
	CellID *uint32 `json:"cell_id,omitempty"`

	TimeoutMs int `json:"timeout_ms,omitempty"`
}

// HandoverERAB is one E-RAB the target eNB admits, with the downlink S1-U
// endpoint it will receive user data on. DLIP defaults to the eNB's S1-U
// address; DLTeid defaults to a synthesized value.
type HandoverERAB struct {
	ID     uint8  `json:"id"`
	DLTeid uint32 `json:"dl_teid,omitempty"`
	DLIP   string `json:"dl_ip,omitempty"`
}

// MigrateENBUERequest relocates a UE context to the target eNB after an S1
// handover, optionally overriding its S1AP ID pair to the target's values.
type MigrateENBUERequest struct {
	TargetENBID string  `json:"target_enb_id"`
	MMEUES1APID *uint32 `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID *uint32 `json:"enb_ue_s1ap_id,omitempty"`
}

type SendENBNASResponse struct {
	S1AP *s1ap.S1APResponse  `json:"s1ap,omitempty"`
	NAS  *naseps.NASResponse `json:"nas,omitempty"`
	// MACVerified reports whether a protected downlink's NAS-MAC verified under
	// the independently-derived keys (set for the Security Mode Command).
	MACVerified *bool `json:"mac_verified,omitempty"`
}
