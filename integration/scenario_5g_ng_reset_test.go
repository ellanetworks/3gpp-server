// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type ngapConnection struct {
	amf int64
	ran int64
}

func (c ngapConnection) String() string {
	return fmt.Sprintf("(amf=%d ran=%d)", c.amf, c.ran)
}

func formatConnections(conns []ngapConnection) string {
	parts := make([]string, 0, len(conns))
	for _, c := range conns {
		parts = append(parts, c.String())
	}

	return "[" + strings.Join(parts, " ") + "]"
}

func ngapResetConnections(t *testing.T, body []byte) []ngapConnection {
	t.Helper()

	var top struct {
		NGAP struct {
			ResetConnections []struct {
				AMFUENGAPID *int64 `json:"amf_ue_ngap_id"`
				RANUENGAPID *int64 `json:"ran_ue_ngap_id"`
			} `json:"reset_connections"`
		} `json:"ngap"`
	}

	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("decode NG Reset Acknowledge: %v\n  body: %s", err, body)
	}

	var conns []ngapConnection

	for i, c := range top.NGAP.ResetConnections {
		if c.AMFUENGAPID == nil && c.RANUENGAPID == nil {
			continue
		}

		if c.AMFUENGAPID == nil || c.RANUENGAPID == nil {
			t.Errorf("NG Reset Acknowledge connection %d omits an AP ID that the NG RESET carried; both must be echoed (TS 38.413 §8.7.4.2.2)\n  body: %s", i, body)
			continue
		}

		conns = append(conns, ngapConnection{amf: *c.AMFUENGAPID, ran: *c.RANUENGAPID})
	}

	return conns
}

func assertNGResetEchoes(t *testing.T, body []byte, want []ngapConnection, context string) {
	t.Helper()

	got := ngapResetConnections(t, body)
	if len(got) != len(want) {
		t.Fatalf("%s: NG Reset Acknowledge echoed %s, want %s — every reset connection must be reported (TS 38.413 §8.7.4.2.2)\n  body: %s",
			context, formatConnections(got), formatConnections(want), body)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: NG Reset Acknowledge connection %d = %s, want %s — items must be in the order received (TS 38.413 §8.7.4.2.2)\n  body: %s",
				context, i, got[i], want[i], body)
		}
	}
}

func mustNGReset(t *testing.T, gnbID string, ueIDs ...string) []byte {
	t.Helper()

	ids, err := json.Marshal(ueIDs)
	if err != nil {
		t.Fatalf("marshal reset_ue_ids: %v", err)
	}

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap",
		fmt.Sprintf(`{"message_type":"ng_reset","reset_ue_ids":%s}`, ids))
	if status != 200 {
		t.Fatalf("ng_reset %v: HTTP %d\n  body: %s", ueIDs, status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapNGResetAcknowledge {
		t.Fatalf("ng_reset %v: ngap.message_type = %q, want NGResetAcknowledge (TS 38.413 §8.7.4)\n  body: %s", ueIDs, got, body)
	}

	return body
}

func Test5GNGReset_All(t *testing.T) {
	gnbID := mustCreateGnB(t)
	ueID := mustCreateUE(t, gnbID)

	doRegistrationFlow(t, gnbID, ueID)

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ngap",
		`{"message_type":"ng_reset"}`)
	if status != 200 {
		t.Fatalf("ng_reset: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "ngap.message_type"); got != ngapNGResetAcknowledge {
		t.Fatalf("ngap.message_type = %q, want NGResetAcknowledge (TS 38.413 §8.7.4)\n  body: %s", got, body)
	}

	status, body = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("uplink NAS after ng_reset: HTTP %d\n  body: %s", status, body)
	}

	// The AP IDs the reset removed are unknown to the AMF (TS 38.413 §10.6).
	if got := jsonGet(body, "ngap.message_type"); got != ngapErrorIndication {
		t.Errorf("uplink NAS on the reset association: ngap.message_type = %q, want ErrorIndication — the AMF must release all allocated resources and remove the NGAP ID (TS 38.413 §8.7.4.2.2)\n  body: %s", got, body)
	}
}

func Test5GNGReset_Partial(t *testing.T) {
	gnbID := mustCreateGnB(t)

	ueA := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueA)

	ueB := mustCreateUE(t, gnbID)
	doRegistrationFlow(t, gnbID, ueB)

	amfA, ranA := ueNGAPIDs(t, gnbID, ueA)
	amfB, ranB := ueNGAPIDs(t, gnbID, ueB)

	want := []ngapConnection{{amf: amfB, ran: ranB}, {amf: amfA, ran: ranA}}

	assertNGResetEchoes(t, mustNGReset(t, gnbID, ueB, ueA), want, "reset of two known connections")

	// The first reset removed both associations, so the repeat drives the
	// unknown-connection branch of TS 38.413 §8.7.4.2.2.
	assertNGResetEchoes(t, mustNGReset(t, gnbID, ueB, ueA), want, "reset of two unknown connections")
}
