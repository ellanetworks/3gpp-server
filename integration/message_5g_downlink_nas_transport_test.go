// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Tests for DownlinkNASTransport (TS 38.413 §9.2.5.2) decode.
// We trigger a DownlinkNASTransport by sending an InitialUEMessage, then verify
// that every IE the AMF includes in the response is properly decoded and surfaced
// in the JSON.

package integration_test

import (
	"encoding/json"
	"testing"
)

func Test5GDownlinkNASTransport_Decode(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d: %s", status, body)
	}

	t.Run("NGAP layer", func(t *testing.T) {
		if got := jsonGet(body, "ngap.pdu_type"); got != "initiating_message" {
			t.Errorf("pdu_type = %q, want initiating_message", got)
		}
		if got := jsonGet(body, "ngap.message_type"); got != ngapDownlinkNASTransport {
			t.Errorf("message_type = %q, want DownlinkNASTransport", got)
		}
		if got := jsonGet(body, "ngap.raw_hex"); got == "" {
			t.Error("raw_hex is empty")
		}
	})

	t.Run("mandatory IEs decoded", func(t *testing.T) {
		var resp struct {
			NGAP struct {
				IEs []struct {
					ID          int64   `json:"id"`
					Criticality string  `json:"criticality"`
					AmfUeNgapID *int64  `json:"amf_ue_ngap_id,omitempty"`
					RanUeNgapID *int64  `json:"ran_ue_ngap_id,omitempty"`
					NasPDU      *string `json:"nas_pdu,omitempty"`
				} `json:"ies"`
			} `json:"ngap"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		var foundAMFID, foundRANID, foundNAS bool
		for _, ie := range resp.NGAP.IEs {
			switch {
			case ie.AmfUeNgapID != nil:
				foundAMFID = true
				if *ie.AmfUeNgapID <= 0 {
					t.Errorf("amf_ue_ngap_id = %d, want > 0", *ie.AmfUeNgapID)
				}
				if ie.ID != 10 {
					t.Errorf("AMF UE NGAP ID ie.id = %d, want 10", ie.ID)
				}
			case ie.RanUeNgapID != nil:
				foundRANID = true
				if *ie.RanUeNgapID <= 0 {
					t.Errorf("ran_ue_ngap_id = %d, want > 0", *ie.RanUeNgapID)
				}
				if ie.ID != 85 {
					t.Errorf("RAN UE NGAP ID ie.id = %d, want 85", ie.ID)
				}
			case ie.NasPDU != nil:
				foundNAS = true
				if *ie.NasPDU == "" {
					t.Error("nas_pdu is empty string")
				}
				if ie.ID != 38 {
					t.Errorf("NAS-PDU ie.id = %d, want 38", ie.ID)
				}
			}
		}

		if !foundAMFID {
			t.Error("missing AMF UE NGAP ID (IE 10) in response")
		}
		if !foundRANID {
			t.Error("missing RAN UE NGAP ID (IE 85) in response")
		}
		if !foundNAS {
			t.Error("missing NAS-PDU (IE 38) in response")
		}
	})

	t.Run("NAS PDU decoded as AuthenticationRequest", func(t *testing.T) {
		if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
			t.Fatalf("nas.message_type = %q, want authentication_request", got)
		}
		if got := jsonGet(body, "nas.security_header_type"); got != "plain" {
			t.Errorf("security_header_type = %q, want plain", got)
		}

		rand := jsonGet(body, "nas.rand")
		if rand == "" {
			t.Error("RAND is empty")
		} else if len(rand) != 32 {
			t.Errorf("RAND length = %d hex chars, want 32 (16 bytes)", len(rand))
		}

		autn := jsonGet(body, "nas.autn")
		if autn == "" {
			t.Error("AUTN is empty")
		} else if len(autn) != 32 {
			t.Errorf("AUTN length = %d hex chars, want 32 (16 bytes)", len(autn))
		}

		abba := jsonGet(body, "nas.abba")
		if abba == "" {
			t.Error("ABBA is empty")
		}

		ngKSI := jsonGet(body, "nas.ng_ksi")
		if ngKSI == "" {
			t.Error("ng_ksi is empty")
		}

		if got := jsonGet(body, "nas.raw_hex"); got == "" {
			t.Error("nas.raw_hex is empty")
		}
	})

	t.Run("IE criticality values", func(t *testing.T) {
		var resp struct {
			NGAP struct {
				IEs []struct {
					ID          int64  `json:"id"`
					Criticality string `json:"criticality"`
				} `json:"ies"`
			} `json:"ngap"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, ie := range resp.NGAP.IEs {
			if ie.Criticality == "" {
				t.Errorf("IE %d has empty criticality", ie.ID)
			}
			switch ie.Criticality {
			case "reject", "ignore", "notify":
			default:
				t.Errorf("IE %d has unexpected criticality %q", ie.ID, ie.Criticality)
			}
		}
	})
}
