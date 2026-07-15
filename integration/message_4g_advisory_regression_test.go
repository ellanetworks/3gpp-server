// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// The 4G NAS (nas/eps) and S1AP codecs are separate from the 5G (nas/5gs, ngap)
// ones, so a fix on the 5G side does not cover them: these tests check the 4G
// control plane against the denial-of-service classes in Ella Core's published 5G
// advisories. The MME has no panic recovery, so any unguarded parse crashes the
// whole core — each test asserts the core survives by attaching a fresh UE
// afterward.

// Test4GMalformedAuthNASNoCrash is the 4G analogue of GHSA-55q8-2gwx-29pc (panic
// on NAS auth messages with missing IEs): the MME must discard them without
// crashing.
func Test4GMalformedAuthNASNoCrash(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := attachChallenge(t, enbID)

	malformed := []string{
		"0753",       // Authentication Response, no RES LV
		"075300",     // Authentication Response, RES length 0
		"075308",     // Authentication Response, RES length 8 but absent
		"075c",       // Authentication Failure, no EMM cause
		"075c15",     // Authentication Failure (synch), no AUTS IE
		"075c153000", // Authentication Failure, AUTS IEI present, bad length
	}

	for _, raw := range malformed {
		nasBody(t, enbID, ueID, fmt.Sprintf(`{"message_type":"inject_nas","raw_nas_pdu":%q,"timeout_ms":1500}`, raw))
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// Test4GShortProtectedNASNoCrash is the 4G analogue of GHSA-m9pm-w3gv-c68f
// (panic on a short integrity-protected NAS payload): the MME must reject a NAS
// message shorter than a full security header (header, 4-octet MAC, sequence)
// without an out-of-bounds read.
func Test4GShortProtectedNASNoCrash(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	// 0x27 = security header type 2 (integrity-protected and ciphered), PD EMM.
	short := []string{"27", "2700", "270000", "2700000000", "270000000000"}

	for _, raw := range short {
		nasBody(t, enbID, ueID, fmt.Sprintf(`{"message_type":"inject_nas","raw_nas_pdu":%q,"timeout_ms":1500}`, raw))
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// Test4GPathSwitchEmptySecCapNoCrash is the 4G analogue of GHSA-j478-p7vq-3347
// (panic on empty NR security capability in PathSwitchRequest). The 4G S1AP
// encoding uses fixed 16-bit bitmaps, so the MME must handle zeroed UE security
// capabilities without crashing.
func Test4GPathSwitchEmptySecCapNoCrash(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"path_switch","path_switch_eea":0,"path_switch_eia":0}`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestAcknowledge" && got != "PathSwitchRequestFailure" {
		t.Fatalf("path switch with zero sec caps: s1ap.message_type = %q, want a defined response; body: %s", got, resp)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
