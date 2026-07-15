// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// Test4GAuthenticationRepeatedSynchFailure sends a synch failure (#21) twice in
// a row. The first is mandatory to act on: per TS 24.301 §5.4.2.7 e) the network
// re-synchronises with the returned AUTS and re-challenges with a fresh vector.
//
// For the second, NOTE 3 of the same subclause says the network "may terminate
// the authentication procedure by sending an AUTHENTICATION REJECT message" —
// permission, not obligation, so re-synchronising once more is equally
// conformant. The binding invariant is that an unauthenticated UE must not reach
// security activation.
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

// Test4GIdentityResponseMalformed checks the MME stays healthy when a UE in the
// Identity procedure returns a malformed Identity Response: the message must be
// discarded without crashing (TS 24.301 §5.4.4). Each PDU is an EMM plain header
// (0x07) for an Identity Response (0x56) with a truncated or empty mobile
// identity.
func Test4GIdentityResponseMalformed(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	// A foreign GUTI drives the MME to run the Identity procedure (§5.4.4).
	resp := nasBody(t, enbID, ueID, `{"message_type":"attach_request","foreign_guti":true}`)
	if got := jsonGet(resp, "nas.message_type"); got != "identity_request" {
		t.Fatalf("foreign-GUTI attach: nas.message_type = %q, want identity_request; body: %s", got, resp)
	}

	malformed := []string{
		"0756",             // header only, no mobile identity
		"075608",           // identity length 8 declared, none present
		"075600",           // identity length 0
		"0756ffffffffffff", // garbage identity octets
	}

	for _, raw := range malformed {
		nasBody(t, enbID, ueID, fmt.Sprintf(`{"message_type":"inject_nas","raw_nas_pdu":%q,"timeout_ms":1500}`, raw))
	}

	// The MME must remain healthy: a fresh UE still attaches.
	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
