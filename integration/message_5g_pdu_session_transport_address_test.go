// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"testing"
)

type pduSessionSetupItem struct {
	PDUSessionID int64  `json:"pdu_session_id"`
	ULTeid       uint32 `json:"ul_teid"`
	UPFN3IP      string `json:"upf_n3_ip"`
	UPFN3IPv6    string `json:"upf_n3_ipv6"`
}

func ngapPDUSessionSetupItems(body []byte) []pduSessionSetupItem {
	var top struct {
		NGAP struct {
			Items []pduSessionSetupItem `json:"pdu_session_setup_items"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	return top.NGAP.Items
}

// TS 38.414 §5.3 makes the 32-, 128- and 160-bit forms all conformant, so no
// particular address family is demanded.
func Test5GPDUSessionResourceSetup_TransportLayerAddress(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, setup := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("pdu_session_establishment_request: HTTP %d\n  body: %s", status, setup)
	}

	if got := jsonGet(setup, "ngap.message_type"); got != ngapPDUSessionResourceSetupRequest {
		t.Fatalf("ngap.message_type = %q, want PDUSessionResourceSetupRequest\n  body: %s", got, setup)
	}

	items := ngapPDUSessionSetupItems(setup)
	if len(items) == 0 {
		t.Fatalf("PDU Session Resource Setup Request carries no setup item\n  body: %s", setup)
	}

	item := items[0]

	if item.UPFN3IP == "" && item.UPFN3IPv6 == "" {
		t.Fatalf("UL NG-U UP TNL Information carries no decodable Transport Layer Address; it must be 32, 128 or 160 bits (TS 38.414 §5.3)\n  body: %s", setup)
	}

	if item.UPFN3IP != "" && item.UPFN3IP != n3IPv4.upfN3 {
		t.Errorf("upf_n3_ip = %q, want the UPF N3 IPv4 %q — with both families signalled the IPv4 occupies the first 32 bits (TS 38.414 §5.3)\n  body: %s",
			item.UPFN3IP, n3IPv4.upfN3, setup)
	}

	if item.UPFN3IPv6 != "" && item.UPFN3IPv6 != n3IPv6.upfN3 {
		t.Errorf("upf_n3_ipv6 = %q, want the UPF N3 IPv6 %q — a 160-bit address carries the IPv6 in the 128 bits following the IPv4 (TS 38.414 §5.3)\n  body: %s",
			item.UPFN3IPv6, n3IPv6.upfN3, setup)
	}
}
