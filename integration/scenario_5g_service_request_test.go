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

// idleRegisteredUE leaves the UE RM-REGISTERED / CM-IDLE with a PDU session, the
// precondition for a Service Request.
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

// A signalling-type Service Request asks for no user-plane reactivation.
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

// A normal deregistration afterwards is what proves the UE reached CM-CONNECTED.
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

// With no security context the request goes out plain with a zeroed 5G-S-TMSI, so
// it reaches the AMF. A SERVICE REQUEST must be integrity protected (TS 24.501
// §4.4.4.2), so an unprotected one from an unknown UE may draw either a 5GMM
// STATUS or a SERVICE REJECT; only the security property is asserted: service
// must not be granted.
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

// idleRegisteredUENoSession leaves the UE CM-IDLE having never established a PDU
// session.
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

// Claiming no active PDU sessions must draw a signalling-style reactivation, with
// no session set up.
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

// A UE claiming a PDU session the AMF does not hold must be reconciled against
// the AMF's view and still accepted.
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

// A Service Request from a still-CM-CONNECTED UE is out-of-state, so either an
// accept on the new connection or a reject is conformant; only a hang is not.
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

// With no context left for a deregistered UE, the AMF must answer with a SERVICE
// REJECT (TS 24.501 §5.6.1.5).
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

// The first request brings the UE to CM-CONNECTED, making the second an
// out-of-state already-connected request; neither must hang.
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

// Behaviour varies by service type and by whether the UE is emergency-registered,
// so only liveness is asserted.
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

// Malformed NAS payloads ride an otherwise-valid Initial UE Message + 5G-S-TMSI,
// so they reach the AMF, which must answer and not leave the request hanging.
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
			// A local build rejection (400/500) and an AMF answer are both
			// acceptable; only a 504 hang is not.
			if status == 504 {
				t.Fatalf("service request hung (HTTP 504)\n  body: %s", body)
			}
		})
	}
}

// A Service Request opens a fresh connection via Initial UE Message, which
// carries no AMF UE NGAP ID, so the forged override is inert and the AMF must
// serve the request normally.
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
