// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

// NASResponse is the decoded form of a downlink EPS NAS message returned as JSON.
// At most the fields relevant to the decoded message type are set.
type NASResponse struct {
	MessageType        string `json:"message_type"`
	RawHex             string `json:"raw_hex"`
	SecurityHeaderType string `json:"security_header_type,omitempty"`

	// Authentication Request (TS 24.301 §8.2.7)
	RAND string `json:"rand,omitempty"`
	AUTN string `json:"autn,omitempty"`
	KSI  *int   `json:"nas_key_set_identifier,omitempty"`

	// Security Mode Command (TS 24.301 §8.2.20)
	CipheringAlgorithm             *int   `json:"ciphering_algorithm,omitempty"`
	IntegrityAlgorithm             *int   `json:"integrity_algorithm,omitempty"`
	ReplayedUESecurityCapabilities string `json:"replayed_ue_security_capabilities,omitempty"`
	IMEISVRequested                *bool  `json:"imeisv_requested,omitempty"`

	// Attach Accept (TS 24.301 §8.2.1) and embedded default bearer
	EPSAttachResult   *int      `json:"eps_attach_result,omitempty"`
	GUTI              *GUTIJSON `json:"guti,omitempty"`
	EPSBearerIdentity *int      `json:"eps_bearer_identity,omitempty"`
	BearerPTI         *int      `json:"bearer_pti,omitempty"`
	PDNAddress        string    `json:"pdn_address,omitempty"`
	APN               string    `json:"apn,omitempty"`
	BearerESMCause    *int      `json:"bearer_esm_cause,omitempty"`

	// Reject / status causes
	EMMCause *int `json:"emm_cause,omitempty"`

	// ESMCause is the session-management cause in a PDN Connectivity Reject, PDN
	// Disconnect Reject, or Deactivate EPS Bearer Context Request (TS 24.301
	// §9.9.4.4).
	ESMCause *int `json:"esm_cause,omitempty"`

	// Identity Request (TS 24.301 §8.2.18)
	IdentityType *int `json:"identity_type,omitempty"`

	// Tracking Area Update Accept (TS 24.301 §8.2.26)
	EPSUpdateResult *int `json:"eps_update_result,omitempty"`
}

// GUTIJSON is an assigned GUTI (TS 24.301 §9.9.3.12).
type GUTIJSON struct {
	MCC        string `json:"mcc"`
	MNC        string `json:"mnc"`
	MMEGroupID int    `json:"mme_group_id"`
	MMECode    int    `json:"mme_code"`
	MTMSI      string `json:"m_tmsi"`
}
