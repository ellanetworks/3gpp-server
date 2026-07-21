// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

// 5GS decouples the PDU session from registration, so the Initial Context Setup
// Request carries the UE-AMBR and the PDU-session setup list only when reactivating
// an idle UE's user plane on Service Request. The twin of Test4GInitialContextSetup_*.
func reactivationICS(t *testing.T, gnbID, ueID string) []byte {
	t.Helper()

	status, ics := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 200 {
		t.Fatalf("service_request: HTTP %d\n  body: %s", status, ics)
	}

	if got := jsonGet(ics, "ngap.message_type"); got != ngapInitialContextSetupRequest {
		t.Fatalf("service_request: ngap.message_type = %q, want InitialContextSetupRequest\n  body: %s", got, ics)
	}

	return ics
}

func Test5GInitialContextSetup_UEAMBR(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)
	ics := reactivationICS(t, gnbID, ueID)

	if dl := jsonGet(ics, "ngap.ue_aggregate_max_bit_rate.dl"); dl == "" || dl == "0" {
		t.Fatalf("ICS Request UE-AMBR dl = %q, want a non-zero provisioned value (TS 38.413 §9.3.1.58)\n  body: %s", dl, ics)
	}

	if ul := jsonGet(ics, "ngap.ue_aggregate_max_bit_rate.ul"); ul == "" || ul == "0" {
		t.Fatalf("ICS Request UE-AMBR ul = %q, want a non-zero provisioned value (TS 38.413 §9.3.1.58)\n  body: %s", ul, ics)
	}
}

// TS 38.414 §5.3 makes the 32-, 128- and 160-bit forms all conformant, so no
// particular address family is demanded.
func Test5GInitialContextSetup_TransportLayerAddress(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)
	ics := reactivationICS(t, gnbID, ueID)

	items := ngapPDUSessionSetupItems(ics)
	if len(items) == 0 {
		t.Fatalf("reactivation ICS carries no PDU-session setup item; the UL NG-U UP Transport Layer Information is mandatory (TS 38.413 §9.2.2.1, §9.3.2.2)\n  body: %s", ics)
	}

	item := items[0]

	if item.TransportLayerAddress == "" && item.TransportLayerAddressIPv6 == "" {
		t.Fatalf("ICS PDU-session setup item carries no decodable Transport Layer Address; it must be 32, 128 or 160 bits (TS 38.414 §5.3)\n  body: %s", ics)
	}

	if item.TransportLayerAddress != "" && item.TransportLayerAddress != n3IPv4.upfN3 {
		t.Errorf("transport_layer_address = %q, want the UPF N3 IPv4 %q (TS 38.414 §5.3)\n  body: %s",
			item.TransportLayerAddress, n3IPv4.upfN3, ics)
	}

	if item.TransportLayerAddressIPv6 != "" && item.TransportLayerAddressIPv6 != n3IPv6.upfN3 {
		t.Errorf("transport_layer_address_ipv6 = %q, want the UPF N3 IPv6 %q (TS 38.414 §5.3)\n  body: %s",
			item.TransportLayerAddressIPv6, n3IPv6.upfN3, ics)
	}
}
