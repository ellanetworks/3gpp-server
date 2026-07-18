// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// TS 36.413 §10.6: a message bearing an unknown local or inconsistent remote UE
// S1AP ID is answered with an Error Indication before the carried NAS PDU is
// examined, so mutating the inner NAS cannot change the outcome.
func Test4GUplinkNASTransport_CrossFuzz(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "stale MME-UE-S1AP-ID + valid NAS",
			body: `{"message_type":"inject_nas","mme_ue_s1ap_id_override":4294967295,"raw_nas_pdu":"0752","timeout_ms":3000}`,
		},
		{
			name: "zero eNB-UE-S1AP-ID + garbage NAS",
			body: `{"message_type":"inject_nas","enb_ue_s1ap_id_override":0,"raw_nas_pdu":"deadbeefcafebabe","timeout_ms":3000}`,
		},
		{
			name: "inconsistent eNB-UE-S1AP-ID + empty NAS",
			body: `{"message_type":"inject_nas","enb_ue_s1ap_id_override":16777215,"raw_nas_pdu":"","timeout_ms":3000}`,
		},
		{
			name: "both IDs zero + plain NAS",
			body: `{"message_type":"inject_nas","mme_ue_s1ap_id_override":0,"enb_ue_s1ap_id_override":0,"raw_nas_pdu":"0741","timeout_ms":3000}`,
		},
		{
			name: "max IDs + truncated NAS",
			body: `{"message_type":"inject_nas","mme_ue_s1ap_id_override":4294967295,"enb_ue_s1ap_id_override":16777215,"raw_nas_pdu":"07","timeout_ms":3000}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID := mustCreateENBUE(t, enbID)

			fullAttach(t, enbID, ueID)

			assertEPSErrorIndication(t, nasBody(t, enbID, ueID, tt.body))
		})
	}
}
