// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// User-plane diagnostics. A user-plane assertion that fails ("no downlink
// arrived") says nothing about where the packet went. Ella Core already counts
// every XDP verdict, FIB-lookup result and byte volume; sampling those counters
// around the step under test turns such a failure into evidence: whether the
// packet was dropped, by which guard, on which interface, and whether it ever
// reached the data network.

package integration_test

import (
	"bufio"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// upfCounterPrefixes are the Ella Core metric families that describe a packet's
// fate in the UPF data path.
var upfCounterPrefixes = []string{
	"app_xdp_action_total",            // XDP verdict per interface (XDP_DROP is the fate we chase)
	"app_xdp_fib_lookup_total",        // routing result: success / no_neigh / blackhole / unreachable
	"app_xdp_source_spoof_drop_total", // UE source anti-spoofing guard
	"app_xdp_ifindex_mismatch_total",
	"app_uplink_bytes",
	"app_downlink_bytes",
}

// upfCounters maps a metric's full `name{labels}` identity to its value.
type upfCounters map[string]float64

// scrapeUPFCounters reads Ella Core's Prometheus endpoint. It never fails the
// test: diagnostics must not turn a real failure into a confusing one.
func scrapeUPFCounters(t *testing.T) upfCounters {
	t.Helper()

	resp, err := http.Get(ellaAPIURL + "/api/v1/metrics")
	if err != nil {
		t.Logf("diag: scrape UPF counters: %v", err)
		return nil
	}
	defer resp.Body.Close()

	out := make(upfCounters)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		wanted := false

		for _, p := range upfCounterPrefixes {
			if strings.HasPrefix(line, p) {
				wanted = true
				break
			}
		}

		if !wanted {
			continue
		}

		sep := strings.LastIndex(line, " ")
		if sep < 0 {
			continue
		}

		v, err := strconv.ParseFloat(line[sep+1:], 64)
		if err != nil {
			continue
		}

		out[line[:sep]] = v
	}

	return out
}

// upfDelta reports the UPF counters that moved since before, so a failing
// user-plane assertion names the packet's fate, not only its absence.
func upfDelta(t *testing.T, before upfCounters) string {
	t.Helper()

	after := scrapeUPFCounters(t)
	if before == nil || after == nil {
		return "  upf counters: unavailable"
	}

	lines := make([]string, 0, len(after))

	for k, v := range after {
		if d := v - before[k]; d != 0 {
			lines = append(lines, fmt.Sprintf("    %s %+g", k, d))
		}
	}

	if len(lines) == 0 {
		return "  upf counters: no change (the packet never reached the UPF data path)"
	}

	sort.Strings(lines)

	return "  upf counters (delta):\n" + strings.Join(lines, "\n")
}
