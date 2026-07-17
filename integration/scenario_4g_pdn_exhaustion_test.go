// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"strconv"
	"testing"
)

// exhaust4gAPN is provisioned in TestMain with an IPv4 /30 pool: two host addresses.
const exhaust4gAPN = "exhaust4g"

const exhaustConnectPTI = 8

// TS 24.301 §6.5.1.4.1: the PDN CONNECTIVITY REJECT ESM cause IE "typically indicates
// one of the following ESM cause values". Because the list is not exhaustive nor pinned
// to a single value, a conformant MME may pick any of these for an exhausted pool.
func pdnConnectivityRejectCauseAllowed(c string) bool {
	switch c {
	case "8", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "38",
		"50", "51", "53", "54", "55", "57", "58", "61", "65", "66":
		return true
	}

	n, err := strconv.Atoi(c)
	if err != nil {
		return false
	}

	return n >= 95 && n <= 111
}

// connectExhaustPDN attaches ue and requests a stand-alone PDN connection on the
// exhaust APN, returning the allocated EBI on acceptance or "" on a reject.
func connectExhaustPDN(t *testing.T, enbID, ueID string) (ebi string, rejected bool) {
	t.Helper()

	resp := nasBody(t, enbID, ueID,
		fmt.Sprintf(`{"message_type":"pdn_connectivity","apn":%q,"pti":%d,"timeout_ms":4000}`, exhaust4gAPN, exhaustConnectPTI))

	switch got := jsonGet(resp, "nas.message_type"); got {
	case "activate_default_eps_bearer_context_request":
		got := jsonGet(resp, "nas.eps_bearer_identity")
		if got == "" {
			t.Fatalf("accepted PDN connection missing EPS bearer identity; body: %s", resp)
		}

		return got, false
	case "pdn_connectivity_reject":
		if pti := jsonGet(resp, "nas.bearer_pti"); pti != strconv.Itoa(exhaustConnectPTI) {
			t.Errorf("PDN CONNECTIVITY REJECT bearer_pti = %q, want %d — the reject must carry the request PTI (TS 24.301 §6.5.1.4.1); body: %s",
				pti, exhaustConnectPTI, resp)
		}

		if c := jsonGet(resp, "nas.esm_cause"); !pdnConnectivityRejectCauseAllowed(c) {
			t.Errorf("PDN CONNECTIVITY REJECT esm_cause = %q, want a cause from the TS 24.301 §6.5.1.4.1 set; body: %s", c, resp)
		}

		return "", true
	default:
		t.Fatalf("exhaust PDN connectivity: nas.message_type = %q, want activate_default_eps_bearer_context_request or pdn_connectivity_reject (TS 24.301 §6.5.1.4.1); body: %s", got, resp)

		return "", false
	}
}

func attachExhaustUE(t *testing.T, enbID string) string {
	t.Helper()

	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	return ueID
}

func Test4GPDNConnectivityPoolExhausted(t *testing.T) {
	enbID := mustCreateENB(t)

	// Ella Core state persists across runs and this pool is only two addresses, so
	// every lease taken here must be returned or the next run starts full.
	type lease struct{ ueID, ebi string }
	var leases []lease
	t.Cleanup(func() {
		for _, l := range leases {
			doRequest(t, "POST", "/enb/"+enbID+"/ue/"+l.ueID+"/nas",
				fmt.Sprintf(`{"message_type":"pdn_disconnect","linked_ebi":%s,"pti":9,"timeout_ms":2000}`, l.ebi))
		}
	})
	connect := func(ueID string) (string, bool) {
		ebi, rejected := connectExhaustPDN(t, enbID, ueID)
		if !rejected {
			leases = append(leases, lease{ueID, ebi})
		}
		return ebi, rejected
	}

	ue1 := attachExhaustUE(t, enbID)
	firstEBI, rejected := connect(ue1)
	if rejected {
		t.Fatalf("first PDN connection on an empty pool was rejected; the /30 pool should have a free address")
	}

	ue2 := attachExhaustUE(t, enbID)
	if _, rejected := connect(ue2); rejected {
		t.Fatalf("second PDN connection was rejected; the /30 pool should have two host addresses")
	}

	// The pool holds two host addresses, so the third connection must be rejected.
	ue3 := attachExhaustUE(t, enbID)
	if _, rejected := connect(ue3); !rejected {
		t.Fatalf("third PDN connection on an exhausted /30 pool was accepted (TS 24.301 §6.5.1.4.1)")
	}

	// Disconnecting the first PDN returns its address to the pool; the third UE then succeeds.
	disc := nasBody(t, enbID, ue1,
		fmt.Sprintf(`{"message_type":"pdn_disconnect","linked_ebi":%s,"pti":9,"timeout_ms":4000}`, firstEBI))
	if got := jsonGet(disc, "nas.message_type"); got != "deactivate_eps_bearer_context_request" {
		t.Fatalf("release exhaust PDN: nas.message_type = %q, want deactivate_eps_bearer_context_request (TS 24.301 §6.5.2.3); body: %s", got, disc)
	}

	if _, rejected := connect(ue3); rejected {
		t.Fatalf("PDN connection was rejected after an address was freed; the pool should have a free lease")
	}
}
