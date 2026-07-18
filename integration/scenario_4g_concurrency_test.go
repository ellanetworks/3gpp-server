// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// attachENBUEConcurrent creates and attaches a UE, returning its id. It runs on its
// own goroutine and must not touch *testing.T.
func attachENBUEConcurrent(enbID, imsi string) (string, error) {
	createBody := fmt.Sprintf(`{"imsi":%q,"k":%q,"opc":%q,"amf":"8000","sqn":"000000000000"}`, imsi, testK, testOPc)

	status, body, err := post("/enb/"+enbID+"/ue", createBody)
	if err != nil {
		return "", err
	}

	if status != 201 {
		return "", fmt.Errorf("create ue: HTTP %d: %s", status, body)
	}

	ueID := jsonGet(body, "ue_id")

	steps := []struct{ msg, wantNAS string }{
		{"attach_request", "authentication_request"},
		{"authentication_response", "security_mode_command"},
		{"security_mode_complete", "attach_accept"},
		{"attach_complete", ""},
	}

	for _, s := range steps {
		status, body, err := post("/enb/"+enbID+"/ue/"+ueID+"/s1ap", fmt.Sprintf(`{"message_type":%q}`, s.msg))
		if err != nil {
			return "", err
		}

		if status != 200 {
			return "", fmt.Errorf("%s: HTTP %d: %s", s.msg, status, body)
		}

		if s.wantNAS != "" {
			if got := jsonGet(body, "nas.message_type"); got != s.wantNAS {
				return "", fmt.Errorf("%s: nas.message_type = %q, want %q", s.msg, got, s.wantNAS)
			}
		}
	}

	return ueID, nil
}

func detachENBUEConcurrent(enbID, ueID string) error {
	status, body, err := post("/enb/"+enbID+"/ue/"+ueID+"/s1ap", `{"message_type":"detach_request"}`)
	if err != nil {
		return err
	}

	if status != 200 {
		return fmt.Errorf("detach ue %s: HTTP %d: %s", ueID, status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != "detach_accept" {
		return fmt.Errorf("detach ue %s: nas.message_type = %q, want detach_accept (TS 24.301 §5.5.2.2.2)", ueID, got)
	}

	return nil
}

func connectPDNENBUEConcurrent(enbID, ueID string) (string, error) {
	status, body, err := post("/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		`{"message_type":"pdn_connectivity","apn":"internet46","timeout_ms":4000}`)
	if err != nil {
		return "", err
	}

	if status != 200 {
		return "", fmt.Errorf("pdn connectivity ue %s: HTTP %d: %s", ueID, status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != "activate_default_eps_bearer_context_request" {
		return "", fmt.Errorf("pdn connectivity ue %s: nas.message_type = %q, want activate_default_eps_bearer_context_request", ueID, got)
	}

	addr := jsonGet(body, "nas.pdn_address")
	if addr == "" {
		return "", fmt.Errorf("pdn connectivity ue %s: no PDN address in Activate Default request", ueID)
	}

	return addr, nil
}

func Test4GConcurrentDetach(t *testing.T) {
	enbID := mustCreateENB(t)

	const n = 6

	supis := claimSubscribers(t, n)
	ueIDs := make([]string, n)

	runParallel(t, n, func(i int) error {
		id, err := attachENBUEConcurrent(enbID, supis[i][len("imsi-"):])
		ueIDs[i] = id

		return err
	})

	runParallel(t, n, func(i int) error {
		if ueIDs[i] == "" {
			return fmt.Errorf("UE %d not attached", i)
		}

		return detachENBUEConcurrent(enbID, ueIDs[i])
	})

	// A fresh attach after the detach barrage proves the MME is still serving.
	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

func Test4GConcurrentPDNConnect(t *testing.T) {
	enbID := mustCreateENB(t)

	const n = 6

	supis := claimSubscribers(t, n)
	ueIDs := make([]string, n)

	runParallel(t, n, func(i int) error {
		id, err := attachENBUEConcurrent(enbID, supis[i][len("imsi-"):])
		ueIDs[i] = id

		return err
	})

	addrs := make([]string, n)

	runParallel(t, n, func(i int) error {
		if ueIDs[i] == "" {
			return fmt.Errorf("UE %d not attached", i)
		}

		addr, err := connectPDNENBUEConcurrent(enbID, ueIDs[i])
		addrs[i] = addr

		return err
	})

	seen := map[string]int{}

	for i, addr := range addrs {
		if addr == "" {
			continue // worker error already reported by runParallel
		}

		if prev, ok := seen[addr]; ok {
			t.Errorf("PDN address %s shared by UE %d and UE %d — IP allocator race", addr, prev, i)
			continue
		}

		seen[addr] = i
	}
}
