// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Concurrency: many UEs driving the same procedure at once on a shared gNB
// association. These exercise the AMF/SMF allocators (AMF UE NGAP ID, 5G-GUTI,
// UE IP) that a race could make hand the same identity to two simultaneous UEs.
// A failure means Ella Core's per-UE state is not isolated under load, not a
// quirk of how it sequences work.

package integration_test

import (
	"fmt"
	"testing"
)

// Test5GConcurrentRegistration registers many distinct subscribers simultaneously
// on one gNB. The AMF must assign each a unique AMF UE NGAP ID (unique per
// AMF–RAN association, TS 38.413 §9.3.3.1) and a unique 5G-GUTI (TS 23.501
// §5.9.4). A shared value betrays an allocator race.
func Test5GConcurrentRegistration(t *testing.T) {
	gnb := createGnBWithID(t, "00c001", "conc-reg")

	const n = 8

	supis := claimSubscribers(t, n)
	results := make([]regResult, n)

	runParallel(t, n, func(i int) error {
		r, err := registerSUPI(gnb, supis[i])
		results[i] = r

		return err
	})

	seenAmf := map[int64]int{}
	seenGuti := map[string]int{}

	for i, r := range results {
		if r.ueID == "" {
			continue // worker error already reported by runParallel
		}

		amf := ueAmfNgapID(t, gnb, r.ueID)
		if amf == 0 {
			t.Errorf("UE %d: AMF UE NGAP ID not assigned", i)
		} else if prev, ok := seenAmf[amf]; ok {
			t.Errorf("AMF UE NGAP ID %d shared by UE %d and UE %d — allocator race (TS 38.413 §9.3.3.1)", amf, prev, i)
		} else {
			seenAmf[amf] = i
		}

		if r.guti == "" {
			t.Errorf("UE %d: no 5G-GUTI in Registration Accept", i)
		} else if prev, ok := seenGuti[r.guti]; ok {
			t.Errorf("5G-GUTI %s shared by UE %d and UE %d — allocator race (TS 23.501 §5.9.4)", r.guti, prev, i)
		} else {
			seenGuti[r.guti] = i
		}
	}
}

// Test5GConcurrentPDUSessionEstablishment has many registered UEs establish a PDU
// session at the same time. The SMF must allocate each a distinct UE IP from the
// pool (TS 23.501 §5.8.2.2); a duplicate means the IP allocator raced.
func Test5GConcurrentPDUSessionEstablishment(t *testing.T) {
	gnb := createGnBWithID(t, "00c002", "conc-pdu")

	const n = 6

	supis := claimSubscribers(t, n)
	ueIDs := make([]string, n)

	runParallel(t, n, func(i int) error {
		r, err := registerSUPI(gnb, supis[i])
		ueIDs[i] = r.ueID

		return err
	})

	ips := make([]string, n)

	runParallel(t, n, func(i int) error {
		if ueIDs[i] == "" {
			return fmt.Errorf("UE %d not registered", i)
		}

		ip, err := establishSession(gnb, ueIDs[i], 1)
		ips[i] = ip

		return err
	})

	seen := map[string]int{}

	for i, ip := range ips {
		if ip == "" {
			t.Errorf("UE %d: no PDU address in Establishment Accept", i)
			continue
		}

		if prev, ok := seen[ip]; ok {
			t.Errorf("UE IP %s shared by UE %d and UE %d — IP allocator race (TS 23.501 §5.8.2.2)", ip, prev, i)
			continue
		}

		seen[ip] = i
	}
}

// Test5GConcurrentDeregistration registers many UEs, deregisters them all at once,
// then re-registers them all at once. The identities freed by the simultaneous
// release must be cleanly reusable: the second wave must again get distinct AMF
// UE NGAP IDs, with no collision, leak, or double-assignment.
func Test5GConcurrentDeregistration(t *testing.T) {
	gnb := createGnBWithID(t, "00c003", "conc-dereg")

	const n = 6

	// Both waves register the same subscribers, so the second re-registers the
	// identities the first released.
	supis := claimSubscribers(t, n)
	first := make([]regResult, n)

	runParallel(t, n, func(i int) error {
		r, err := registerSUPI(gnb, supis[i])
		first[i] = r

		return err
	})

	runParallel(t, n, func(i int) error {
		if first[i].ueID == "" {
			return fmt.Errorf("UE %d not registered", i)
		}

		return deregister(gnb, first[i].ueID)
	})

	second := make([]regResult, n)

	runParallel(t, n, func(i int) error {
		r, err := registerSUPI(gnb, supis[i])
		second[i] = r

		return err
	})

	seen := map[int64]int{}

	for i, r := range second {
		if r.ueID == "" {
			continue
		}

		amf := ueAmfNgapID(t, gnb, r.ueID)
		if amf == 0 {
			t.Errorf("UE %d: AMF UE NGAP ID not reassigned after dereg + re-register", i)
		} else if prev, ok := seen[amf]; ok {
			t.Errorf("AMF UE NGAP ID %d shared by UE %d and UE %d after dereg + re-register — stale or double-allocated", amf, prev, i)
		} else {
			seen[amf] = i
		}
	}
}
