// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

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
				AMFUENGAPID *int64  `json:"amf_ue_ngap_id,omitempty"`
				RANUENGAPID *int64  `json:"ran_ue_ngap_id,omitempty"`
				NasPDU      *string `json:"nas_pdu,omitempty"`
			} `json:"ngap"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		switch {
		case resp.NGAP.AMFUENGAPID == nil:
			t.Error("missing AMF UE NGAP ID in response")
		case *resp.NGAP.AMFUENGAPID <= 0:
			t.Errorf("amf_ue_ngap_id = %d, want > 0", *resp.NGAP.AMFUENGAPID)
		}

		switch {
		case resp.NGAP.RANUENGAPID == nil:
			t.Error("missing RAN UE NGAP ID in response")
		case *resp.NGAP.RANUENGAPID <= 0:
			t.Errorf("ran_ue_ngap_id = %d, want > 0", *resp.NGAP.RANUENGAPID)
		}

		switch {
		case resp.NGAP.NasPDU == nil:
			t.Error("missing NAS-PDU in response")
		case *resp.NGAP.NasPDU == "":
			t.Error("nas_pdu is empty string")
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

}
