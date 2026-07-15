// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

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
