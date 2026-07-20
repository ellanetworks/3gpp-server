// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

// tgtGNB is the target's store ID (URL paths); tgtGNBHex is its NGAP gNB ID.
func handoverHop(t *testing.T, srcGNB, ueID, tgtGNB, tgtGNBHex string) int64 {
	t.Helper()

	const tgtRan = 100

	status, body := doRequest(t, "POST", "/gnb/"+srcGNB+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"handover_required","target_gnb_id":"%s"}`, tgtGNBHex))
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

func Test5GN2HandoverPingPong(t *testing.T) {
	const hexA, hexB = "0000c0", "0000c1"
	gnbA := createGNBWithID(t, hexA, "ho-pp-a")
	gnbB := createGNBWithID(t, hexB, "ho-pp-b")

	ueID := establishRegisteredUE(t, gnbA)

	handoverHop(t, gnbA, ueID, gnbB, hexB)
	handoverHop(t, gnbB, ueID, gnbA, hexA)

	assertMobilityRegistrationAccepted(t, gnbA, ueID)
}

func Test5GN2HandoverMultiHop(t *testing.T) {
	const hexA, hexB, hexC = "0000c2", "0000c3", "0000c4"
	gnbA := createGNBWithID(t, hexA, "ho-mh-a")
	gnbB := createGNBWithID(t, hexB, "ho-mh-b")
	gnbC := createGNBWithID(t, hexC, "ho-mh-c")

	ueID := establishRegisteredUE(t, gnbA)

	handoverHop(t, gnbA, ueID, gnbB, hexB)
	handoverHop(t, gnbB, ueID, gnbC, hexC)

	assertMobilityRegistrationAccepted(t, gnbC, ueID)
}

func Test5GN2HandoverConcurrentUEs(t *testing.T) {
	srcGNB := createGNBWithID(t, "0002f0", "ho-cc-src")
	tgtHex := "0002f1"
	targetGNB := createGNBWithID(t, tgtHex, "ho-cc-tgt")

	// Dedicated subscribers: a mid-flow abort must not dirty the shared ones.
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

func Test5GN2HandoverThenIdleThenServiceRequest(t *testing.T) {
	gnbA := createGNBWithID(t, "000210", "ho-cyc-a")
	hexB := "000211"
	gnbB := createGNBWithID(t, hexB, "ho-cyc-b")

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
