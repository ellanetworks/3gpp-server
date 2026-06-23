// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"strings"
	"testing"
)

func Test5GNGSetup(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		wantHTTP          int
		wantContain       string
		wantAbsent        string
		wantFailCauseMisc int
	}{
		// --- Happy path ---
		{
			name:        "basic NGSetup MCC=001 MNC=01 SST=1",
			body:        `{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000001","name":"test-gnb-1","sst":1}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name:        "different gNB ID",
			body:        `{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000099","name":"test-gnb-99","sst":1}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name:        "with SD value",
			body:        `{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000003","name":"test-gnb-sd","sst":1,"sd":"000001"}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name:        "long gNB name",
			body:        `{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"01","tac":"000001","gnb_id":"000004","name":"this-is-a-very-long-gnb-name-for-testing-purposes","sst":1}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		// --- Wrong PLMN ---
		{
			name:              "wrong MCC (999/01) → NGSetupFailure",
			body:              `{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"999","mnc":"01","tac":"000001","gnb_id":"000006","name":"test-gnb-wrongmcc","sst":1}`,
			wantHTTP:          201,
			wantContain:       ngapNGSetupFailure,
			wantFailCauseMisc: causeMiscUnknownPLMNOrSNPN,
		},
		{
			name:              "wrong MNC (001/99) → NGSetupFailure",
			body:              `{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"001","mnc":"99","tac":"000001","gnb_id":"000007","name":"test-gnb-wrongmnc","sst":1}`,
			wantHTTP:          201,
			wantContain:       ngapNGSetupFailure,
			wantFailCauseMisc: causeMiscUnknownPLMNOrSNPN,
		},
		{
			name:              "completely wrong PLMN (310/410) → NGSetupFailure",
			body:              `{"amf_address":"10.3.0.2:38412","gnb_n2_address":"10.3.0.3","mcc":"310","mnc":"410","tac":"000001","gnb_id":"000008","name":"test-gnb-us-plmn","sst":1}`,
			wantHTTP:          201,
			wantContain:       ngapNGSetupFailure,
			wantFailCauseMisc: causeMiscUnknownPLMNOrSNPN,
		},
		// --- Custom IE tests ---
		{
			name: "custom IEs valid NGSetup",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000b","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-custom-ies"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			// A missing mandatory (reject-criticality) IE must be rejected. TS 38.413
			// §10.3.5 prefers NG SETUP FAILURE over Error Indication, so assert only
			// that no NG Setup Response is produced, not the rejection form.
			name: "custom IEs missing GlobalRANNodeID",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-no-ranid"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantAbsent: ngapNGSetupResponse,
		},
		{
			name: "custom IEs missing SupportedTAList",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000c","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-no-ta"},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantAbsent: ngapNGSetupResponse,
		},
		{
			name: "custom IEs missing DefaultPagingDRX (AMF accepts it)",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000d","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-no-drx"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}}
				]
			}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name: "custom IEs wrong criticality on GlobalRANNodeID",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"ignore","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000e","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-wrong-crit"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name: "custom IEs reversed order",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"00000f","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-wrong-order"},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name: "custom IEs no RANNodeName (optional omitted)",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000010","gnb_id_bit_length":24}}},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name: "custom IEs multiple slices",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000011","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-multi-slice"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"},{"sst":"02"},{"sst":"03","sd":"000001"}]}]}]}},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name: "custom IEs multiple TAIs",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000012","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-multi-tai"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[
						{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]},
						{"tac":"000002","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}
					]}},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name: "custom IEs PLMN mismatch → NGSetupFailure",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000013","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-plmn-mismatch"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"09f919","slice_support":[{"sst":"01"}]}]}]}},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantHTTP:          201,
			wantContain:       ngapNGSetupFailure,
			wantFailCauseMisc: causeMiscUnknownPLMNOrSNPN,
		},
		{
			// Empty SupportedTAList cannot be encoded (ASN.1 SEQUENCE OF lower bound),
			// so the request never reaches the AMF; the server itself rejects the build.
			name: "custom IEs empty SupportedTAList",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000014","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-empty-ta"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[]}},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantAbsent: ngapNGSetupResponse,
		},
		{
			name: "custom IEs PagingDRX v32",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000015","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-drx-v32"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]}]}]}},
					{"id":21,"criticality":"ignore","default_paging_drx":0}
				]
			}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
		{
			name: "custom IEs multiple broadcast PLMNs",
			body: `{
				"amf_address":"10.3.0.2:38412", "gnb_n2_address":"10.3.0.3",
				"ng_setup_ies": [
					{"id":27,"criticality":"reject","global_ran_node_id":{"present":"global_gnb_id","global_gnb_id":{"plmn_identity":"00f110","gnb_id":"000016","gnb_id_bit_length":24}}},
					{"id":82,"criticality":"ignore","ran_node_name":"test-gnb-multi-bplmn"},
					{"id":102,"criticality":"reject","supported_ta_list":{"items":[{"tac":"000001","broadcast_plmns":[
						{"plmn_identity":"00f110","slice_support":[{"sst":"01"}]},
						{"plmn_identity":"09f919","slice_support":[{"sst":"01"}]}
					]}]}},
					{"id":21,"criticality":"ignore","default_paging_drx":3}
				]
			}`,
			wantHTTP:    201,
			wantContain: ngapNGSetupResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := doRequest(t, "POST", "/gnb", tt.body)

			if tt.wantHTTP != 0 && status != tt.wantHTTP {
				t.Errorf("HTTP status = %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}

			bodyStr := string(body)
			if tt.wantContain != "" && !strings.Contains(bodyStr, tt.wantContain) {
				t.Errorf("body missing %q\n  body: %s", tt.wantContain, bodyStr)
			}
			if tt.wantAbsent != "" && strings.Contains(bodyStr, tt.wantAbsent) {
				t.Errorf("body should not contain %q\n  body: %s", tt.wantAbsent, bodyStr)
			}

			assertNGAPCauseMisc(t, body, "ng_setup_response", tt.wantFailCauseMisc)

			if status == 201 {
				gnbID := jsonGet(body, "gnb_id")
				if gnbID != "" {
					doRequest(t, "DELETE", "/gnb/"+gnbID, "")
				}
			}
		})
	}
}
