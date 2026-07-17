// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"testing"
)

func Test4GDetach_Fuzz(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantHTTP       int
		wantNASMsgType string
	}{
		{
			name:           "valid detach after full attach",
			body:           `{"message_type":"detach_request","timeout_ms":3000}`,
			wantHTTP:       200,
			wantNASMsgType: "detach_accept",
		},
		{
			// 07 plain EMM header, 45 Detach request, 01 EPS-detach ngKSI 0 (not switch off).
			// An unprotected non-switch-off detach fails integrity; the MME authenticates or
			// ignores rather than accepting it (TS 24.301 §4.4.4.3), so no Detach accept arrives.
			name:     "raw NAS: plain normal detach",
			body:     `{"message_type":"detach_request","raw_nas_pdu":"07450100","timeout_ms":2000}`,
			wantHTTP: 504,
		},
		{
			// 09 sets the switch-off bit: TS 24.301 §5.5.2.2.2 sends no Detach Accept,
			// so no DownlinkNASTransport arrives and the wait times out.
			name:     "raw NAS: plain switch-off detach",
			body:     `{"message_type":"detach_request","raw_nas_pdu":"07450900","timeout_ms":2000}`,
			wantHTTP: 504,
		},
		{
			// Same unprotected non-switch-off detach truncated before its mobile identity:
			// still fails integrity, so it is not accepted (TS 24.301 §4.4.4.3) — no reply.
			name:     "raw NAS: truncated (missing mobile identity)",
			body:     `{"message_type":"detach_request","raw_nas_pdu":"074501","timeout_ms":2000}`,
			wantHTTP: 504,
		},
		{
			name:     "raw NAS: empty",
			body:     `{"message_type":"detach_request","raw_nas_pdu":"","timeout_ms":2000}`,
			wantHTTP: 504,
		},
		{
			// PD nibble is not EPS mobility management (TS 24.301 §9.2): discarded, no reply.
			name:     "raw NAS: garbage",
			body:     `{"message_type":"detach_request","raw_nas_pdu":"deadbeefcafebabe","timeout_ms":2000}`,
			wantHTTP: 504,
		},
		{
			// 07 46 = plain Detach accept: a network-originating message in the uplink
			// direction, discarded by the MME (TS 24.301 §7) — no reply.
			name:     "raw NAS: detach accept type (wrong direction)",
			body:     `{"message_type":"detach_request","raw_nas_pdu":"0746","timeout_ms":2000}`,
			wantHTTP: 504,
		},
		{
			// A lone EMM header octet: too short for a message type (TS 24.301 §7.2), ignored.
			name:     "raw NAS: single byte header",
			body:     `{"message_type":"detach_request","raw_nas_pdu":"07","timeout_ms":2000}`,
			wantHTTP: 504,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enbID := mustCreateENB(t)
			ueID := mustCreateENBUE(t, enbID)

			fullAttach(t, enbID, ueID)

			status, body := doRequest(t, "POST", "/enb/"+enbID+"/ue/"+ueID+"/nas", tt.body)
			if status != tt.wantHTTP {
				t.Fatalf("HTTP %d, want %d\n  body: %s", status, tt.wantHTTP, body)
			}

			if tt.wantHTTP != 200 {
				return
			}

			if tt.wantNASMsgType != "" {
				if got := jsonGet(body, "nas.message_type"); got != tt.wantNASMsgType {
					t.Errorf("nas.message_type = %q, want %q\n  body: %s", got, tt.wantNASMsgType, body)
				}
			}
		})
	}
}
