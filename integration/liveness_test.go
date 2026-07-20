// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import "testing"

// assertGNBCoreAlive fails unless a live AMF still accepts a fresh NG association
// and answers a valid registration with an authentication challenge. A test whose
// pass condition is silence (a 504 wait timeout, a message the core conformantly
// ignores) calls this afterward so that a wedged or dead core — also silent —
// cannot make it pass. It builds its own gNB and subscriber, so it holds even
// when the calling test tore its association down or never established one.
func assertGNBCoreAlive(t *testing.T) {
	t.Helper()

	gnbID := mustCreateGNB(t)
	ueID := mustCreateUE(t, gnbID)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request"}`)
	if status != 200 {
		t.Fatalf("core liveness: registration_request HTTP %d, want 200 — the AMF is not responsive\n  body: %s", status, resp)
	}

	if got := jsonGet(resp, "nas.message_type"); got != "authentication_request" {
		t.Fatalf("core liveness: registration drew %q, want authentication_request — the AMF is not answering a valid registration", got)
	}
}

// assertENBCoreAlive is the 4G twin: a live MME accepts a fresh S1 association
// and answers a valid attach with an EPS-AKA challenge.
func assertENBCoreAlive(t *testing.T) {
	t.Helper()

	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	status, resp := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		`{"message_type":"attach_request"}`)
	if status != 200 {
		t.Fatalf("core liveness: attach_request HTTP %d, want 200 — the MME is not responsive\n  body: %s", status, resp)
	}

	if got := jsonGet(resp, "nas.message_type"); got != "authentication_request" {
		t.Fatalf("core liveness: attach drew %q, want authentication_request — the MME is not answering a valid attach", got)
	}
}
