// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Realistic repeated-mobility scenarios: a UE handed over across several gNBs,
// as happens continuously in a live network (TS 38.413 §8.4, TS 23.502
// §4.9.1.3). Each hop must complete and leave the UE consistently served by the
// new gNB.

package integration_test

import (
	"fmt"
	"testing"
)

// handoverHop migrates the UE onto the target once the handover completes, so
// the next hop can originate there. tgtGNB is the target's store ID (URL paths,
// migrate); tgtGnbHex is its NGAP gNB ID (the Handover Required target).
func handoverHop(t *testing.T, srcGNB, ueID, tgtGNB, tgtGnbHex string) int64 {
	t.Helper()

	const tgtRan = 100

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_required","target_gnb_id":"%s"}`, tgtGnbHex))
	if status != 200 {
		t.Fatalf("handover_required %s->%s: HTTP %d\n  body: %s", srcGNB, tgtGNB, status, body)
	}

	hoReq := awaitNGAP(t, tgtGNB, ngapHandoverRequest)
	tgtAmf, ok := ngapFirstAmfUeNgapID(hoReq)
	if !ok {
		t.Fatalf("HandoverRequest missing AMF UE NGAP ID\n  body: %s", hoReq)
	}

	status, body = doRequest(t, "POST", "/gnb/"+tgtGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"}]}`, tgtAmf, tgtRan))
	if status != 200 {
		t.Fatalf("handover_request_acknowledge: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(awaitNGAP(t, srcGNB, ngapHandoverCommand), "ngap.message_type"); got != ngapHandoverCommand {
		t.Fatalf("hop %s->%s: expected HandoverCommand, got %q", srcGNB, tgtGNB, got)
	}

	status, body = doRequest(t, "POST", "/gnb/"+tgtGNB+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_notify","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d}`, tgtAmf, tgtRan))
	if status != 200 {
		t.Fatalf("handover_notify: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/migrate",
		fmt.Sprintf(`{"target_gnb_id":"%s","ran_ue_ngap_id":%d,"amf_ue_ngap_id":%d}`, tgtGNB, tgtRan, tgtAmf))
	if status != 200 {
		t.Fatalf("migrate UE %s->%s: HTTP %d\n  body: %s", srcGNB, tgtGNB, status, body)
	}

	return tgtAmf
}

// An accepted Mobility Registration Update (TS 24.501 §5.5.1.3) over the UE's
// current connection is what proves a moved UE is still usable.
func assertMobilityRegistrationAccepted(t *testing.T, gnbID, ueID string) {
	t.Helper()

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request","registration_type":2,"existing_connection":true}`)
	if status != 200 {
		t.Fatalf("post-handover mobility registration: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasRegistrationAccept {
		t.Errorf("post-handover mobility registration: nas.message_type = %q, want registration_accept\n  body: %s", got, body)
	}
}

// Models a UE oscillating at a cell edge.
func Test5GN2HandoverPingPong(t *testing.T) {
	const hexA, hexB = "0000c0", "0000c1"
	gnbA := createGnBWithID(t, hexA, "ho-pp-a")
	gnbB := createGnBWithID(t, hexB, "ho-pp-b")

	ueID := establishRegisteredUE(t, gnbA)

	handoverHop(t, gnbA, ueID, gnbB, hexB)
	handoverHop(t, gnbB, ueID, gnbA, hexA)

	assertMobilityRegistrationAccepted(t, gnbA, ueID)
}

// Models a UE moving across three cells, A->B->C.
func Test5GN2HandoverMultiHop(t *testing.T) {
	const hexA, hexB, hexC = "0000c2", "0000c3", "0000c4"
	gnbA := createGnBWithID(t, hexA, "ho-mh-a")
	gnbB := createGnBWithID(t, hexB, "ho-mh-b")
	gnbC := createGnBWithID(t, hexC, "ho-mh-c")

	ueID := establishRegisteredUE(t, gnbA)

	handoverHop(t, gnbA, ueID, gnbB, hexB)
	handoverHop(t, gnbB, ueID, gnbC, hexC)

	assertMobilityRegistrationAccepted(t, gnbC, ueID)
}

// With two UEs preparing over the same gNB pair simultaneously, the AMF must
// keep their contexts isolated (distinct AMF UE NGAP IDs) and complete both.
func Test5GN2HandoverConcurrentUEs(t *testing.T) {
	srcGNB := createGnBWithID(t, "0002f0", "ho-cc-src")
	tgtHex := "0002f1"
	targetGNB := createGnBWithID(t, tgtHex, "ho-cc-tgt")

	// Dedicated subscribers so a mid-flow abort here cannot leave the
	// widely-shared subscribers in a dirty state for other tests.
	ue1 := establishRegisteredUEWithSUPI(t, srcGNB, "imsi-001010000000005")
	ue2 := establishRegisteredUEWithSUPI(t, srcGNB, "imsi-001010000000006")

	for _, ue := range []string{ue1, ue2} {
		status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ue+"/ngap",
			fmt.Sprintf(`{"message_type":"handover_required","target_gnb_id":"%s"}`, tgtHex))
		if status != 200 {
			t.Fatalf("handover_required: HTTP %d\n  body: %s", status, body)
		}
	}

	amf1, ok1 := ngapFirstAmfUeNgapID(awaitNGAP(t, targetGNB, ngapHandoverRequest))
	amf2, ok2 := ngapFirstAmfUeNgapID(awaitNGAP(t, targetGNB, ngapHandoverRequest))
	if !ok1 || !ok2 {
		t.Fatal("HandoverRequest missing AMF UE NGAP ID")
	}

	if amf1 == amf2 {
		t.Fatalf("concurrent handovers shared AMF UE NGAP ID %d — UE contexts not isolated", amf1)
	}

	ran := int64(101)
	for _, amf := range []int64{amf1, amf2} {
		status, body := doRequest(t, "POST", "/gnb/"+targetGNB+"/ngap",
			fmt.Sprintf(`{"message_type":"handover_request_acknowledge","amf_ue_ngap_id":%d,"ran_ue_ngap_id":%d,"pdu_sessions":[{"id":1,"dl_teid":9001,"dl_ip":"10.3.0.3"}]}`, amf, ran))
		if status != 200 {
			t.Fatalf("acknowledge: HTTP %d\n  body: %s", status, body)
		}

		if got := jsonGet(awaitNGAP(t, srcGNB, ngapHandoverCommand), "ngap.message_type"); got != ngapHandoverCommand {
			t.Fatalf("expected HandoverCommand, got %q", got)
		}

		completeHandover(t, targetGNB, amf, ran)
		ran++
	}
}

// Models the connected/idle cycle a UE goes through after moving: handover to a
// new gNB, release to CM-IDLE there, then a Service Request to come back to
// CM-CONNECTED (TS 24.501 §5.6.1).
func Test5GN2HandoverThenIdleThenServiceRequest(t *testing.T) {
	gnbA := createGnBWithID(t, "000210", "ho-cyc-a")
	hexB := "000211"
	gnbB := createGnBWithID(t, hexB, "ho-cyc-b")

	ueID := establishRegisteredUE(t, gnbA)
	handoverHop(t, gnbA, ueID, gnbB, hexB)

	status, body := doRequest(t, "POST", "/gnb/"+gnbB+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("ue_context_release_request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Fatalf("release: ngap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbB+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 200 {
		t.Fatalf("service_request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapInitialContextSetupRequest {
		t.Errorf("service_request after handover: ngap.message_type = %q, want InitialContextSetupRequest\n  body: %s", got, body)
	}
}
