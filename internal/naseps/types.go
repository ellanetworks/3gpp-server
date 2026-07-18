// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

type NASResponse struct {
	MessageType        string `json:"message_type"`
	SecurityHeaderType string `json:"security_header_type,omitempty"`

	RAND                string `json:"rand,omitempty"`
	AUTN                string `json:"autn,omitempty"`
	NASKeySetIdentifier *int   `json:"nas_key_set_identifier,omitempty"`

	SelectedCipheringAlgorithm     *int   `json:"selected_ciphering_algorithm,omitempty"`
	SelectedIntegrityAlgorithm     *int   `json:"selected_integrity_algorithm,omitempty"`
	ReplayedUESecurityCapabilities string `json:"replayed_ue_security_capabilities,omitempty"`
	IMEISVRequested                bool   `json:"imeisv_requested,omitempty"`

	GUTI    *GUTIJSON `json:"guti,omitempty"`
	TAIList string    `json:"tai_list,omitempty"`

	EPSAttachResult *int `json:"eps_attach_result,omitempty"`
	EPSUpdateResult *int `json:"eps_update_result,omitempty"`

	EPSBearerIdentity *int   `json:"eps_bearer_identity,omitempty"`
	BearerPTI         *int   `json:"bearer_pti,omitempty"`
	PDNAddress        string `json:"pdn_address,omitempty"`
	APN               string `json:"apn,omitempty"`
	APNAMBR           string `json:"apn_ambr,omitempty"`
	BearerESMCause    *int   `json:"bearer_esm_cause,omitempty"`

	EMMCause *int `json:"emm_cause,omitempty"`
	ESMCause *int `json:"esm_cause,omitempty"`

	IdentityType *int `json:"identity_type,omitempty"`

	RawHex string `json:"raw_hex"`
}

type GUTIJSON struct {
	MCC        string `json:"mcc"`
	MNC        string `json:"mnc"`
	MMEGroupID int    `json:"mme_group_id"`
	MMECode    int    `json:"mme_code"`
	MTMSI      string `json:"m_tmsi"`
}
