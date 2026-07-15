// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test4GAuthenticationRepeatedSynchFailure(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := attachChallenge(t, enbID)

	first := nasBody(t, enbID, ueID, `{"message_type":"authentication_failure","cause":21}`)
	if got := jsonGet(first, "nas.message_type"); got != "authentication_request" {
		t.Fatalf("first synch failure: nas.message_type = %q, want a fresh authentication_request (TS 24.301 §5.4.2.7 e); body: %s", got, first)
	}

	second := nasBody(t, enbID, ueID, `{"message_type":"authentication_failure","cause":21}`)

	switch got := jsonGet(second, "nas.message_type"); got {
	case "authentication_reject", "authentication_request":
		// Both permitted: terminate (§5.4.2.7 NOTE 3) or re-synchronise again (item e).
	default:
		t.Fatalf("repeated synch failure: nas.message_type = %q, want authentication_reject (TS 24.301 §5.4.2.7 NOTE 3) or a further authentication_request (item e); body: %s", got, second)
	}
}

func Test4GIdentityResponseMalformed(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	resp := nasBody(t, enbID, ueID, `{"message_type":"attach_request","foreign_guti":true}`)
	if got := jsonGet(resp, "nas.message_type"); got != "identity_request" {
		t.Fatalf("foreign-GUTI attach: nas.message_type = %q, want identity_request; body: %s", got, resp)
	}

	// 0756 = EMM plain header, Identity Response.
	malformed := []string{
		"0756",             // no mobile identity
		"075608",           // identity length 8 declared, none present
		"075600",           // identity length 0
		"0756ffffffffffff", // garbage identity octets
	}

	for _, raw := range malformed {
		nasBody(t, enbID, ueID, fmt.Sprintf(`{"message_type":"inject_nas","raw_nas_pdu":%q,"timeout_ms":1500}`, raw))
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
