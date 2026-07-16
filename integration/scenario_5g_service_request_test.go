// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func idleRegisteredUE(t *testing.T) (string, string) {
	t.Helper()

	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("pdu_session: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("ue_context_release: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Fatalf("release ngap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}

	return gnbID, ueID
}

func Test5GServiceRequest_Data(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapInitialContextSetupRequest {
		t.Errorf("ngap.message_type = %q, want InitialContextSetupRequest\n  body: %s", got, body)
	}

	// The Service Accept rides in the Initial Context Setup Request's NAS PDU.
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}
}

func Test5GServiceRequest_Signalling(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	body := fmt.Sprintf(`{"message_type":"service_request","service_type":%d}`, serviceTypeSignalling)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
	}

	got := jsonGet(resp, "ngap.message_type")
	if got != ngapInitialContextSetupRequest && got != ngapDownlinkNASTransport {
		t.Errorf("ngap.message_type = %q, want InitialContextSetupRequest or DownlinkNASTransport\n  body: %s", got, resp)
	}
	if nasType := jsonGet(resp, "nas.message_type"); nasType != nasServiceAccept {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", nasType, resp)
	}
}

func Test5GServiceRequest_ThenDeregister(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 200 {
		t.Fatalf("service_request: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Fatalf("service_request nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"deregistration_request"}`)
	if status != 200 {
		t.Fatalf("deregistration: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Errorf("deregistration ngap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}
}

// An unprotected SERVICE REQUEST (TS 24.501 §4.4.4.2) may draw a 5GMM STATUS or a
// SERVICE REJECT, so only the denial of service is asserted.
func Test5GServiceRequest_WithoutRegistration(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status == 504 {
		t.Fatalf("service request hung (HTTP 504) — message may not have reached the AMF\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got == nasServiceAccept {
		t.Errorf("AMF granted service to an unregistered UE (nas.message_type=service_accept)\n  body: %s", body)
	}
}

func idleRegisteredUENoSession(t *testing.T) (string, string) {
	t.Helper()

	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"ue_context_release_request"}`)
	if status != 200 {
		t.Fatalf("ue_context_release: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "ngap.message_type"); got != ngapUEContextReleaseCommand {
		t.Fatalf("release ngap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}

	return gnbID, ueID
}

func Test5GServiceRequest_IdleNoSession(t *testing.T) {
	gnbID, ueID := idleRegisteredUENoSession(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","pdu_session_status":"0000"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Fatalf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}

	assertServiceAcceptPDUSessionStatus(t, body)
}

// TS 24.501 §5.6.1.4.1: a PDU session status IE in the SERVICE REQUEST obliges the
// AMF to include one in the SERVICE ACCEPT.
func assertServiceAcceptPDUSessionStatus(t *testing.T, body []byte) {
	t.Helper()

	if got := jsonGet(body, "nas.pdu_session_status"); got == "" {
		t.Errorf("nas.pdu_session_status is absent, want a PDU session status IE (TS 24.501 §5.6.1.4.1)\n  body: %s", body)
	}
}

func Test5GServiceRequest_PDUStatusMismatch(t *testing.T) {
	gnbID, ueID := idleRegisteredUENoSession(t)

	// pdu_session_status bit 1 (0x0200) claims session 1 active; the AMF holds none.
	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","pdu_session_status":"0200"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Fatalf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}

	assertServiceAcceptPDUSessionStatus(t, body)
}

// Out-of-state: accept and reject are both conformant, so only a hang fails.
func Test5GServiceRequest_WhileConnected(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status == 504 {
		t.Fatalf("service request hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
}

func Test5GServiceRequest_AfterDeregistration(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"deregistration_request"}`)
	if status != 200 {
		t.Fatalf("deregistration: HTTP %d\n  body: %s", status, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status == 504 {
		t.Fatalf("service request hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasServiceReject {
		t.Errorf("nas.message_type = %q, want service_reject (TS 24.501 §5.6.1.5)\n  body: %s", got, body)
	}
}

// The second request is out-of-state: accept and reject are both conformant.
func Test5GServiceRequest_BackToBack(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 200 {
		t.Fatalf("first service_request: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Fatalf("first service_request nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status == 504 {
		t.Fatalf("second service request hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("second service_request: HTTP %d\n  body: %s", status, body)
	}
}

// Response varies by service type and emergency registration, so only liveness is asserted.
func Test5GServiceRequest_ServiceTypes(t *testing.T) {
	tests := []struct {
		name        string
		serviceType int
	}{
		{name: "mobile-terminated", serviceType: serviceTypeMobileTerminatedServices},
		{name: "emergency", serviceType: serviceTypeEmergencyServices},
		{name: "emergency fallback", serviceType: serviceTypeEmergencyServicesFallback},
		{name: "high-priority access", serviceType: serviceTypeHighPriorityAccess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID, ueID := idleRegisteredUE(t)

			body := fmt.Sprintf(`{"message_type":"service_request","service_type":%d}`, tt.serviceType)
			status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
			if status == 504 {
				t.Fatalf("service request hung (HTTP 504)\n  body: %s", resp)
			}
			if status != 200 {
				t.Fatalf("HTTP %d, want 200\n  body: %s", status, resp)
			}
		})
	}
}

func Test5GServiceRequest_Fuzz(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "raw NAS: empty",
			body: `{"message_type":"service_request","raw_nas_pdu":""}`,
		},
		{
			name: "raw NAS: garbage",
			body: `{"message_type":"service_request","raw_nas_pdu":"deadbeefcafebabe"}`,
		},
		{
			name: "raw NAS: plain service request header, no integrity",
			body: `{"message_type":"service_request","raw_nas_pdu":"7e004c"}`,
		},
		{
			name: "service_type out of range",
			body: fmt.Sprintf(`{"message_type":"service_request","service_type":%d}`, serviceTypeOutOfRange),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gnbID, ueID := idleRegisteredUE(t)

			status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", tt.body)
			// A local build rejection (400/500) is as conformant as an AMF answer.
			if status == 504 {
				t.Fatalf("service request hung (HTTP 504)\n  body: %s", body)
			}
		})
	}
}

// Initial UE Message carries no AMF UE NGAP ID, so the override never reaches the AMF.
func Test5GServiceRequest_StaleAMFIDOverride(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","amf_ue_ngap_id_override":99999}`)
	if status == 504 {
		t.Fatalf("service request hung (HTTP 504)\n  body: %s", body)
	}
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}
}
