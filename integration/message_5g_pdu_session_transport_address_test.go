// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"testing"
)

// pduSessionSetupItem is one session of a PDU Session Resource Setup Request,
// carrying the UPF's uplink N3 GTP-U tunnel as the server decodes it from the
// UL NG-U UP TNL Information IE (TS 38.413 §9.3.4.1).
type pduSessionSetupItem struct {
	PDUSessionID int64  `json:"pdu_session_id"`
	ULTeid       uint32 `json:"ul_teid"`
	UPFN3IP      string `json:"upf_n3_ip"`
	UPFN3IPv6    string `json:"upf_n3_ipv6"`
}

// ngapPDUSessionSetupItems returns the PDU Session Resource Setup items carried
// in the response's IE list.
func ngapPDUSessionSetupItems(body []byte) []pduSessionSetupItem {
	var top struct {
		NGAP struct {
			IEs []struct {
				Items []pduSessionSetupItem `json:"pdu_session_setup_items"`
			} `json:"ies"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}

	for _, ie := range top.NGAP.IEs {
		if len(ie.Items) > 0 {
			return ie.Items
		}
	}

	return nil
}

// Test5GPDUSessionResourceSetup_TransportLayerAddress checks the UPF N3 endpoint
// the AMF signals in the PDU Session Resource Setup Request Transfer's UL NG-U
// UP TNL Information. The Transport Layer Address there is encoded per TS 38.414
// §5.3: "The Transport Layer Address signalled in NGAP messages is a bit string
// of a) 32 bits in case of IPv4 address [...]; or b) 128 bits in case of IPv6
// address [...]; or c) 160 bits if both IPv4 and IPv6 addresses are signalled, in
// which case the IPv4 address is contained in the first 32 bits."
//
// All three forms are conformant, so the test does not demand a particular one:
// it requires that at least one family decodes (a length outside 32/128/160 bits
// yields none) and that every family present names the UPF's N3 address for that
// family — a swapped or truncated 160-bit encoding hands back a v4 address read
// out of the v6 half, or the reverse.
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
