// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"testing"
)

func ngapIEHasUERadioCapability(body []byte, want string) bool {
	var top struct {
		NGAP struct {
			IEs []struct {
				UERadioCapability *string `json:"ue_radio_capability"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return false
	}

	for _, ie := range top.NGAP.IEs {
		if ie.UERadioCapability != nil && *ie.UERadioCapability == want {
			return true
		}
	}

	return false
}

func Test5GUERadioCapabilityReplay(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueID)

	const radioCap = "aabbccddee"

	if s, b := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_capability_info","ue_radio_capability":"`+radioCap+`"}`); s != 200 {
		t.Fatalf("ue_capability_info: HTTP %d\n  body: %s", s, b)
	}

	s, b := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"ue_context_release_request"}`)
	if s != 200 || jsonGet(b, "ngap.message_type") != ngapUEContextReleaseCommand {
		t.Fatalf("release: HTTP %d, %q\n  body: %s", s, jsonGet(b, "ngap.message_type"), b)
	}

	s, b = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", `{"message_type":"service_request"}`)
	if s != 200 || jsonGet(b, "ngap.message_type") != ngapInitialContextSetupRequest {
		t.Fatalf("service_request did not re-establish: HTTP %d, %q\n  body: %s", s, jsonGet(b, "ngap.message_type"), b)
	}

	if !ngapIEHasUERadioCapability(b, radioCap) {
		t.Fatalf("Initial Context Setup Request did not replay the UE radio capability %q (TS 38.413 §8.14.1)\n  body: %s", radioCap, b)
	}
}
