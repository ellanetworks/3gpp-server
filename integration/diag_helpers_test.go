// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

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

var upfCounterPrefixes = []string{
	"app_xdp_action_total",
	"app_xdp_fib_lookup_total",
	"app_xdp_source_spoof_drop_total",
	"app_xdp_ifindex_mismatch_total",
	"app_uplink_bytes",
	"app_downlink_bytes",
}

type upfCounters map[string]float64

func scrapeUPFCounters(t *testing.T) upfCounters {
	t.Helper()

	resp, err := http.Get(ellaAPIURL + "/api/v1/metrics")
	if err != nil {
		t.Logf("diag: scrape UPF counters: %v", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

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
