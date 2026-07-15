// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test4GInitialContextSetup_UEAMBR(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	nasStep(t, enbID, ueID, "attach_request")
	nasStep(t, enbID, ueID, "authentication_response")
	ics := nasStep(t, enbID, ueID, "security_mode_complete")

	if got := jsonGet(ics, "nas.message_type"); got != "attach_accept" {
		t.Fatalf("security_mode_complete: nas.message_type = %q, want attach_accept\n  body: %s", got, ics)
	}

	if dl := jsonGet(ics, "s1ap.ue_aggregate_max_bit_rate.dl"); dl == "" || dl == "0" {
		t.Fatalf("ICS Request UE-AMBR dl = %q, want a non-zero provisioned value (TS 36.413 §9.2.1.20)\n  body: %s", dl, ics)
	}

	if ul := jsonGet(ics, "s1ap.ue_aggregate_max_bit_rate.ul"); ul == "" || ul == "0" {
		t.Fatalf("ICS Request UE-AMBR ul = %q, want a non-zero provisioned value (TS 36.413 §9.2.1.20)\n  body: %s", ul, ics)
	}

	nasStep(t, enbID, ueID, "attach_complete")
}

// TS 36.414 §5.3 makes the 32-, 128- and 160-bit forms all conformant, so no
// particular address family is demanded.
func Test4GInitialContextSetup_TransportLayerAddress(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	nasStep(t, enbID, ueID, "attach_request")
	nasStep(t, enbID, ueID, "authentication_response")
	ics := nasStep(t, enbID, ueID, "security_mode_complete")

	v4 := jsonGet(ics, "s1ap.erab_setup_items.0.transport_layer_address")
	v6 := jsonGet(ics, "s1ap.erab_setup_items.0.transport_layer_address_ipv6")

	if v4 == "" && v6 == "" {
		t.Fatalf("ICS Request E-RAB item carries no decodable Transport Layer Address; it is mandatory (TS 36.413 §9.1.4.1) and must be 32, 128 or 160 bits (TS 36.414 §5.3)\n  body: %s", ics)
	}

	if v4 != "" && v4 != n3IPv4.upfN3 {
		t.Errorf("ICS Request transport_layer_address = %q, want the S-GW S1-U IPv4 %q — with both families signalled the IPv4 occupies the first 32 bits (TS 36.414 §5.3)\n  body: %s",
			v4, n3IPv4.upfN3, ics)
	}

	if v6 != "" && v6 != n3IPv6.upfN3 {
		t.Errorf("ICS Request transport_layer_address_ipv6 = %q, want the S-GW S1-U IPv6 %q — a 160-bit address carries the IPv6 in the 128 bits following the IPv4 (TS 36.414 §5.3)\n  body: %s",
			v6, n3IPv6.upfN3, ics)
	}

	nasStep(t, enbID, ueID, "attach_complete")
}
