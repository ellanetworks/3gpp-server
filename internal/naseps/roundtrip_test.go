// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package naseps

import (
	"encoding/hex"
	"testing"

	"github.com/ellanetworks/core/nas/eps"
)

func TestESMStatusRoundTrip(t *testing.T) {
	const (
		ebi   = 5
		pti   = 3
		cause = 43 // TS 24.301 §9.9.4.4 "invalid EPS bearer identity"
	)

	pdu, err := BuildESMStatus(ebi, pti, cause)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	resp, err := Decode(pdu)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.MessageType != "esm_status" {
		t.Fatalf("message_type = %q, want esm_status", resp.MessageType)
	}

	if resp.EPSBearerIdentity == nil || *resp.EPSBearerIdentity != ebi {
		t.Errorf("eps_bearer_identity = %v, want %d", resp.EPSBearerIdentity, ebi)
	}

	if resp.BearerPTI == nil || *resp.BearerPTI != pti {
		t.Errorf("bearer_pti = %v, want %d", resp.BearerPTI, pti)
	}

	if resp.ESMCause == nil || *resp.ESMCause != cause {
		t.Errorf("esm_cause = %v, want %d", resp.ESMCause, cause)
	}
}

func TestAttachAcceptSurfacesTAIList(t *testing.T) {
	taiList := []byte{0x00, 0x02, 0xf1, 0x10, 0x00, 0x01}

	pdu, err := (&eps.AttachAccept{
		EPSAttachResult:     1,
		TAIList:             taiList,
		ESMMessageContainer: []byte{},
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp, err := Decode(pdu)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.MessageType != "attach_accept" {
		t.Fatalf("message_type = %q, want attach_accept", resp.MessageType)
	}

	if resp.TAIList != hex.EncodeToString(taiList) {
		t.Fatalf("tai_list = %q, want %q", resp.TAIList, hex.EncodeToString(taiList))
	}
}
