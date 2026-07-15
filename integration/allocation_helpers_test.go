// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Test-resource allocation. Ella Core's state persists across tests, so two
// tests sharing a subscriber, an eNB ID or a gNB ID share core state: one test's
// attach, release or teardown is visible to the other, and a failure in either
// can be caused by the other. The allocators here hand every caller an identity
// no other caller holds, which keeps that coupling out of the suite.
//
// Each identity space has two regions:
//   - reserved: fixed values a test names explicitly, because the value itself
//     is under test (an S1 Setup asserting its own eNB ID) or because the test
//     needs several UEs in a known relation (a spoofing victim and attacker).
//   - allocated: drawn from a counter, in a block disjoint from every reserved
//     value, so an allocated identity can never collide with a named one.

package integration_test

import (
	"fmt"
	"sync/atomic"
	"testing"
)

// allocatedSubscriberBase is the first pooled-subscriber index the allocator
// hands out. It sits above the reserved block (1..numTestSubscribers, which
// tests name via testSUPI) and above subscriptionChangeIMSI (index 100), so a
// claimed subscriber never collides with one a test names explicitly.
const allocatedSubscriberBase = 200

// allocatedENBIDBase is the first eNB ID the allocator hands out. It sits above
// every eNB ID a test names explicitly — including the 1..51 range
// Test4GAssociationFlood creates — and below the 20-bit macro eNB ID maximum
// (1048575, itself a named boundary case in message_4g_s1setup_test.go).
const allocatedENBIDBase = 1000

// allocatedGnBIDBase is the first gNB ID the allocator hands out, as a 24-bit
// value rendered to the 6 hex digits the API takes. It sits above every gNB ID a
// test names explicitly.
const allocatedGnBIDBase = 0x0a0000

var (
	subscriberCounter atomic.Int64
	enbIDCounter      atomic.Int64
	gnbIDCounter      atomic.Int64
)

// claimSubscriber returns the SUPI of a subscriber no other caller holds. The
// reserved pool TestMain provisions up front is too small to give every
// UE-creating call site a distinct subscriber, so it provisions on demand.
func claimSubscriber(t *testing.T) string {
	t.Helper()

	i := allocatedSubscriberBase + int(subscriberCounter.Add(1)) - 1
	supi := testSUPI(i)

	if err := createSubscriber(ellaAdminToken, supi[len("imsi-"):]); err != nil {
		t.Fatalf("provision subscriber %s: %v", supi, err)
	}

	return supi
}

func claimSubscribers(t *testing.T, n int) []string {
	t.Helper()

	supis := make([]string, n)
	for i := range supis {
		supis[i] = claimSubscriber(t)
	}

	return supis
}

func claimENBID() int {
	return allocatedENBIDBase + int(enbIDCounter.Add(1)) - 1
}

// claimGnBID renders the ID to the 6-hex-digit form the API takes.
func claimGnBID() string {
	return fmt.Sprintf("%06x", allocatedGnBIDBase+int(gnbIDCounter.Add(1))-1)
}
