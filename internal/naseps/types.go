// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

type NASResponse struct {
	MessageType        string `json:"message_type"`
	RawHex             string `json:"raw_hex"`
	SecurityHeaderType string `json:"security_header_type,omitempty"`

	RAND string `json:"rand,omitempty"`
	AUTN string `json:"autn,omitempty"`
	KSI  *int   `json:"nas_key_set_identifier,omitempty"`

	CipheringAlgorithm             *int   `json:"ciphering_algorithm,omitempty"`
	IntegrityAlgorithm             *int   `json:"integrity_algorithm,omitempty"`
	ReplayedUESecurityCapabilities string `json:"replayed_ue_security_capabilities,omitempty"`
	IMEISVRequested                *bool  `json:"imeisv_requested,omitempty"`

	EPSAttachResult   *int      `json:"eps_attach_result,omitempty"`
	GUTI              *GUTIJSON `json:"guti,omitempty"`
	TAIList           string    `json:"tai_list,omitempty"`
	EPSBearerIdentity *int      `json:"eps_bearer_identity,omitempty"`
	BearerPTI         *int      `json:"bearer_pti,omitempty"`
	PDNAddress        string    `json:"pdn_address,omitempty"`
	APN               string    `json:"apn,omitempty"`
	BearerESMCause    *int      `json:"bearer_esm_cause,omitempty"`

	EMMCause *int `json:"emm_cause,omitempty"`

	ESMCause *int `json:"esm_cause,omitempty"`

	IdentityType *int `json:"identity_type,omitempty"`

	EPSUpdateResult *int `json:"eps_update_result,omitempty"`

	APNAMBR string `json:"apn_ambr,omitempty"`
}

type GUTIJSON struct {
	MCC        string `json:"mcc"`
	MNC        string `json:"mnc"`
	MMEGroupID int    `json:"mme_group_id"`
	MMECode    int    `json:"mme_code"`
	MTMSI      string `json:"m_tmsi"`
}
