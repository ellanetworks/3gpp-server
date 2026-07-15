// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"sync/atomic"
	"testing"
)

const (
	allocatedSubscriberBase = subscriptionChangeIndex + 100
	allocatedENBIDBase      = 1000
	allocatedGnBIDBase      = 0x0a0000
)

var (
	subscriberCounter atomic.Int64
	enbIDCounter      atomic.Int64
	gnbIDCounter      atomic.Int64
)

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

func claimGnBID() string {
	return fmt.Sprintf("%06x", allocatedGnBIDBase+int(gnbIDCounter.Add(1))-1)
}
