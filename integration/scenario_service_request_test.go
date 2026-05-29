//go:build integration

// Tests for the Service Request procedure (TS 24.501 §5.6.1). A registered UE
// that has gone CM-IDLE (after a UE Context Release) sends a Service Request to
// return to CM-CONNECTED. The AMF re-activates the UE context via Initial
// Context Setup and the UE receives a Service Accept.

package integration_test

import (
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
	if got := jsonGet(body, "ngap.message_type"); got != "UEContextReleaseCommand" {
		t.Fatalf("release ngap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}

	return gnbID, ueID
}

// TestServiceRequest_Data drives the canonical data Service Request: an idle UE
// reconnects and the AMF re-activates its PDU session via Initial Context
// Setup, then the UE gets a Service Accept.
func TestServiceRequest_Data(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	// The AMF reactivates the session via Initial Context Setup Request.
	if got := jsonGet(body, "ngap.message_type"); got != "InitialContextSetupRequest" {
		t.Errorf("ngap.message_type = %q, want InitialContextSetupRequest\n  body: %s", got, body)
	}

	// The Service Accept rides in the Initial Context Setup Request's NAS PDU.
	if got := jsonGet(body, "nas.message_type"); got != "service_accept" {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}
}

// TestServiceRequest_Signalling sends a signalling-type Service Request (no
// user-plane reactivation). The AMF should accept it.
func TestServiceRequest_Signalling(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request","service_type":0}`)
	if status != 200 {
		t.Fatalf("HTTP %d, want 200\n  body: %s", status, body)
	}

	got := jsonGet(body, "ngap.message_type")
	if got != "InitialContextSetupRequest" && got != "DownlinkNASTransport" {
		t.Errorf("ngap.message_type = %q, want InitialContextSetupRequest or DownlinkNASTransport\n  body: %s", got, body)
	}
	if nasType := jsonGet(body, "nas.message_type"); nasType != "service_accept" {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", nasType, body)
	}
}

// TestServiceRequest_ThenDeregister verifies the UE is fully CM-CONNECTED after
// a Service Request by running a normal deregistration afterward.
func TestServiceRequest_ThenDeregister(t *testing.T) {
	gnbID, ueID := idleRegisteredUE(t)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 200 {
		t.Fatalf("service_request: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "nas.message_type"); got != "service_accept" {
		t.Fatalf("service_request nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"deregistration_request"}`)
	if status != 200 {
		t.Fatalf("deregistration: HTTP %d\n  body: %s", status, body)
	}
	if got := jsonGet(body, "ngap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("deregistration ngap.message_type = %q, want UEContextReleaseCommand\n  body: %s", got, body)
	}
}

// TestServiceRequest_WithoutRegistration sends a Service Request for a UE that
// was never registered (no security context / GUTI). The server rejects it
// locally with HTTP 400.
func TestServiceRequest_WithoutRegistration(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"service_request"}`)
	if status != 400 {
		t.Fatalf("HTTP %d, want 400 (no security context)\n  body: %s", status, body)
	}
}

// TestServiceRequest_Fuzz sends Service Requests with malformed/raw NAS payloads
// over an otherwise-valid Initial UE Message + 5G-S-TMSI. The AMF must respond,
// never silently drop.
func TestServiceRequest_Fuzz(t *testing.T) {
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
			name: "service_type out of range (7)",
			body: `{"message_type":"service_request","service_type":7}`,
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
func TestServiceRequest_StaleAMFIDOverride(t *testing.T) {
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
	if got := jsonGet(body, "nas.message_type"); got != "service_accept" {
		t.Errorf("nas.message_type = %q, want service_accept\n  body: %s", got, body)
	}
}
