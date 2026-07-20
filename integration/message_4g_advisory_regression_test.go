// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"fmt"
	"testing"
)

func Test4GMalformedAuthNASNoCrash(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := attachChallenge(t, enbID)

	malformed := []string{
		"0753",       // Authentication Response, no RES LV
		"075300",     // Authentication Response, RES length 0
		"075308",     // Authentication Response, RES length 8 but absent
		"075c",       // Authentication Failure, no EMM cause
		"075c15",     // Authentication Failure (synch), no AUTS IE
		"075c153000", // Authentication Failure, AUTS IEI present, bad length
	}

	for _, raw := range malformed {
		nasBody(t, enbID, ueID, fmt.Sprintf(`{"message_type":"inject_nas","raw_nas_pdu":%q,"timeout_ms":1500}`, raw))
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

func Test4GShortProtectedNASNoCrash(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	// 0x27 = security header type 2 (integrity-protected and ciphered), PD EMM.
	short := []string{"27", "2700", "270000", "2700000000", "270000000000"}

	for _, raw := range short {
		nasBody(t, enbID, ueID, fmt.Sprintf(`{"message_type":"inject_nas","raw_nas_pdu":%q,"timeout_ms":1500}`, raw))
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}

// All bits zero encodes "no algorithm other than EEA0/EIA0" (TS 36.413 §9.2.1.40), a legal report that mismatches the UE's stored caps.
func Test4GPathSwitchEmptySecCapNoCrash(t *testing.T) {
	enbID := mustCreateENB(t)
	ueID := mustCreateENBUE(t, enbID)

	fullAttach(t, enbID, ueID)

	resp := pathSwitchUE(t, enbID, ueID, `,"path_switch_eea":0,"path_switch_eia":0`)

	if got := jsonGet(resp, "s1ap.message_type"); got != "PathSwitchRequestAcknowledge" {
		t.Fatalf("path switch with zero sec caps: s1ap.message_type = %q, want PathSwitchRequestAcknowledge; body: %s", got, resp)
	}

	if eea := jsonGet(resp, "s1ap.replayed_ue_security_capabilities.encryption_algorithms"); eea != storedUESecurityCapabilities {
		t.Errorf("replayed encryption algorithms = %q, want %s (the stored value, TS 33.401 §7.2.4.2.2); body: %s", eea, storedUESecurityCapabilities, resp)
	}

	if eia := jsonGet(resp, "s1ap.replayed_ue_security_capabilities.integrity_protection_algorithms"); eia != storedUESecurityCapabilities {
		t.Errorf("replayed integrity algorithms = %q, want %s (the stored value, TS 33.401 §7.2.4.2.2); body: %s", eia, storedUESecurityCapabilities, resp)
	}

	fresh := mustCreateENBUE(t, enbID)
	fullAttach(t, enbID, fresh)
}
