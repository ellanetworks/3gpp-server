// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Tests for the Service Request procedure (TS 24.501 §5.6.1). A registered UE
// that has gone CM-IDLE (after a UE Context Release) sends a Service Request to
// return to CM-CONNECTED. The AMF re-activates the UE context via Initial
// Context Setup and the UE receives a Service Accept.

package integration_test

import (
	"fmt"
	"testing"
)

// idleRegisteredUE registers a UE, establishes a PDU session, then releases the
// RAN connection so the UE is RM-REGISTERED / CM-IDLE — the precondition for a
// Service Request. Returns the gNB and UE IDs.
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

// TestServiceRequest_Data drives the canonical data Service Request: an idle UE
// reconnects and the AMF re-activates its PDU session via Initial Context
// Setup, then the UE gets a Service Accept.
func Test5GServiceRequest_Data(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	// The AMF reactivates the session via Initial Context Setup Request.
	if got := jsonGet(body, "ngap.message_type"); got != ngapInitialContextSetupRequest {
		t.Errorf("ngap.message_type = %q, want InitialContextSetupRequest\n  body: %s", got, body)
	}

	// The Service Accept rides in the Initial Context Setup Request's NAS PDU.
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}
}

// TestServiceRequest_Signalling sends a signalling-type Service Request (no
// user-plane reactivation). The AMF should accept it.
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

// TestServiceRequest_ThenDeregister verifies the UE is fully CM-CONNECTED after
// a Service Request by running a normal deregistration afterward.
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

// TestServiceRequest_WithoutRegistration sends a Service Request for a UE that
// was never registered. The server sends it plain (no security context) with a
// zeroed 5G-S-TMSI so it reaches the AMF, which must NOT grant service to an
// unknown, unprotected UE. The exact rejection form is not pinned: a SERVICE
// REQUEST must be integrity protected (TS 24.501 §4.4.4.2), so an unprotected
// one from an unknown UE may be answered either with a 5GMM STATUS (protocol
// error) or a SERVICE REJECT — both satisfy the security property. We only
// assert service is not granted.
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

	// The AMF must not accept an unprotected Service Request from an unknown UE.
	if got := jsonGet(body, "nas.message_type"); got == nasServiceAccept {
		t.Errorf("AMF granted service to an unregistered UE (nas.message_type=service_accept)\n  body: %s", body)
	}
}

// idleRegisteredUENoSession registers a UE and releases it without ever
// establishing a PDU session — CM-IDLE with no active session.
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

// TestServiceRequest_IdleNoSession sends a Service Request claiming no active
// PDU sessions from an idle UE that never had one. The AMF should accept it
// (signalling-style reactivation) without trying to set up any session.
func Test5GServiceRequest_IdleNoSession(t *testing.T) {
	gnbID, ueID := idleRegisteredUENoSession(t)

	// pdu_session_status "0000" => claim no active sessions.
	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","pdu_session_status":"0000"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}
}

// TestServiceRequest_PDUStatusMismatch claims an active PDU session (id 1) the
// AMF does not have (the UE never established one). The AMF must reconcile and
// still accept the Service Request, not error out.
func Test5GServiceRequest_PDUStatusMismatch(t *testing.T) {
	gnbID, ueID := idleRegisteredUENoSession(t)

	// bit 1 set => claim session 1 active; AMF has none.
	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","pdu_session_status":"0200"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}
}

// TestServiceRequest_WhileConnected sends a Service Request while the UE is
// still CM-CONNECTED (no prior release). This is out-of-state; the AMF must
// respond (accept on the new connection or reject), never hang.
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

// TestServiceRequest_AfterDeregistration sends a Service Request after the UE
// has fully deregistered. With no context for the UE, the AMF must answer with
// a SERVICE REJECT (TS 24.501 §5.6.1.5).
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

// TestServiceRequest_BackToBack sends two Service Requests in a row. The first
// brings the UE to CM-CONNECTED; the second is therefore an out-of-state
// (already-connected) request. Neither must hang.
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

// TestServiceRequest_ServiceTypes exercises the remaining service types from an
// idle UE. Behaviour varies by type (and whether the UE is emergency-
// registered), so we assert the AMF responds and does not hang.
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

// TestServiceRequest_Fuzz sends Service Requests with malformed/raw NAS payloads
// over an otherwise-valid Initial UE Message + 5G-S-TMSI. The AMF must respond,
// never silently drop.
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
			// Either the server rejects the build locally (400/500) or the AMF
			// answers; what must not happen is a 504 hang.
			if status == 504 {
				t.Fatalf("service request hung (HTTP 504)\n  body: %s", body)
			}
		})
	}
}

// TestServiceRequest_NGAPIDFuzz forges the AMF UE NGAP ID on the Uplink path is
// not applicable here (Service Request opens a fresh connection via Initial UE
// Message). Instead we forge the RAN UE NGAP ID override and confirm the AMF
// still produces a usable response or an Error Indication, never a hang.
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
	// Initial UE Message carries no AMF UE NGAP ID, so the override is inert;
	// the AMF should still process the service request normally.
	if got := jsonGet(body, "nas.message_type"); got != nasServiceAccept {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}
}
