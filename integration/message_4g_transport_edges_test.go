// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"testing"
)

func Test4GDownlinkNASTransport_Decode(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		`{"message_type":"attach_request"}`)
	if status != 200 {
		t.Fatalf("HTTP %d: %s", status, body)
	}

	t.Run("S1AP layer", func(t *testing.T) {
		if got := jsonGet(body, "s1ap.pdu_type"); got != "initiating_message" {
			t.Errorf("pdu_type = %q, want initiating_message", got)
		}
		if got := jsonGet(body, "s1ap.message_type"); got != "DownlinkNASTransport" {
			t.Errorf("message_type = %q, want DownlinkNASTransport", got)
		}
		if got := jsonGet(body, "s1ap.raw_hex"); got == "" {
			t.Error("raw_hex is empty")
		}
	})

	t.Run("mandatory IEs decoded", func(t *testing.T) {
		var resp struct {
			S1AP struct {
				MMEUES1APID *int64  `json:"mme_ue_s1ap_id,omitempty"`
				ENBUES1APID *int64  `json:"enb_ue_s1ap_id,omitempty"`
				NASPDU      *string `json:"nas_pdu,omitempty"`
			} `json:"s1ap"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		switch {
		case resp.S1AP.MMEUES1APID == nil:
			t.Error("missing MME UE S1AP ID in response")
		case *resp.S1AP.MMEUES1APID <= 0:
			t.Errorf("mme_ue_s1ap_id = %d, want > 0", *resp.S1AP.MMEUES1APID)
		}

		switch {
		case resp.S1AP.ENBUES1APID == nil:
			t.Error("missing eNB UE S1AP ID in response")
		case *resp.S1AP.ENBUES1APID <= 0:
			t.Errorf("enb_ue_s1ap_id = %d, want > 0", *resp.S1AP.ENBUES1APID)
		}

		switch {
		case resp.S1AP.NASPDU == nil:
			t.Error("missing NAS-PDU in response")
		case *resp.S1AP.NASPDU == "":
			t.Error("nas_pdu is empty string")
		}
	})

	t.Run("NAS PDU decoded as AuthenticationRequest", func(t *testing.T) {
		if got := jsonGet(body, "nas.message_type"); got != "authentication_request" {
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

		// EPS AKA carries a NAS key set identifier, not the 5GS ABBA/ng-KSI (TS 24.301 §8.2.7).
		if got := jsonGet(body, "nas.nas_key_set_identifier"); got == "" {
			t.Error("nas_key_set_identifier is absent")
		}

		if got := jsonGet(body, "nas.raw_hex"); got == "" {
			t.Error("nas.raw_hex is empty")
		}
	})
}

// TS 36.413 §8.7.2 leaves the receiver's reaction implementation-specific, so
// only an Error Indication in return is failed.
func Test4GErrorIndicationBuild(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, ueID)

	status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/s1ap",
		`{"message_type":"error_indication","timeout_ms":3000}`)
	if status == 200 {
		if got := jsonGet(body, "s1ap.message_type"); got == "ErrorIndication" {
			t.Fatalf("MME answered a valid Error Indication with an Error Indication (TS 36.413 §8.7.2)\n  body: %s", body)
		}
	}
}
