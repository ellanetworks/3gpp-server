// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// Test4GAttachRequestAllOptionalIEs sends an ATTACH REQUEST carrying every
// optional IE the message defines (TS 24.301 Table 8.2.4.1) and asserts the MME
// accepts it and proceeds to authentication.
func Test4GAttachRequestAllOptionalIEs(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	body := `{
		"message_type":"attach_request",
		"old_ptmsi_signature":"010203",
		"additional_guti":"f110000201030003e6",
		"last_visited_registered_tai":"00f1103039",
		"drx_parameter":"0008",
		"ms_network_capability":"e5e034",
		"old_location_area_identification":"00f1100001",
		"tmsi_status":1,
		"mobile_station_classmark_2":"3319a2",
		"mobile_station_classmark_3":"6014",
		"supported_codecs":"04026004",
		"additional_update_type":2,
		"voice_domain_preference":"0004",
		"device_properties":1,
		"old_guti_type":0,
		"ms_network_feature_support":1,
		"tmsi_based_nri_container":"0000",
		"t3324_value":"21",
		"t3412_extended_value":"0a",
		"extended_drx_parameters":"2b",
		"ue_additional_security_capability":"00000000",
		"ue_status":"01",
		"additional_information_requested":"01",
		"n1_ue_network_capability":"00",
		"ue_radio_capability_id_availability":"01",
		"requested_wus_assistance_information":"01",
		"drx_parameter_nb_s1_mode":"00",
		"requested_imsi_offset":"0001"
	}`

	resp := nasBody(t, enbID, ueID, body)

	if got := jsonGet(resp, "nas.message_type"); got != "authentication_request" {
		t.Fatalf("attach_request with all optional IEs: nas.message_type = %q, want authentication_request; body: %s", got, resp)
	}
}
