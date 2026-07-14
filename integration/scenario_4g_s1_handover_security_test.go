// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// S1 handover cross-association abuse (TS 36.413 §10.6): a rogue eNB must not be
// able to start a handover of another eNB's UE by forging its S1AP ID pair on its
// own association. The MME must answer the rogue with an Error Indication and
// leave the victim's connection intact. A failure means Ella Core deviates.

package integration_test

import (
	"fmt"
	"testing"
)

// Test4GS1HandoverCrossENBHijack checks a rogue eNB cannot hand over another
// eNB's UE. The attacker sends a HANDOVER REQUIRED carrying the victim's
// (MME-UE-S1AP-ID, eNB-UE-S1AP-ID) pair on its own association. Because that pair
// names a UE-associated connection on a different association, the MME must
// answer the attacker with an Error Indication (TS 36.413 §10.6) and must not
// disturb the victim.
func Test4GS1HandoverCrossENBHijack(t *testing.T) {
	victimENB := createENBWithID(t, 1, "victim-enb")
	attackerENB := createENBWithID(t, 2, "attacker-enb")

	victimUE := mustCreateENBUE(t, victimENB)
	fullAttach(t, victimENB, victimUE)

	vMME, vENB := enbUES1APIDs(t, victimENB, victimUE)

	// The attacker needs only its own association up; the UE is the API vehicle.
	attackerUE := mustCreateENBUE(t, attackerENB)

	status, body := doRequest(t, "POST", "/enb/"+attackerENB+"/ue/"+attackerUE+"/nas",
		fmt.Sprintf(`{"message_type":"handover_required","target_enb_id":%q,"mme_ue_s1ap_id":%s,"enb_ue_s1ap_id":%s}`,
			victimENB, vMME, vENB))
	if status != 200 {
		t.Fatalf("handover_required (forged): HTTP %d\n  body: %s", status, body)
	}

	// The MME must reject the rogue request with an Error Indication on the
	// attacker's association, not prepare a handover of the victim.
	ei := awaitENBS1AP(t, attackerENB, `["ErrorIndication","HandoverPreparationFailure"]`)
	if got := jsonGet(ei, "s1ap.message_type"); got != "ErrorIndication" {
		t.Errorf("s1ap.message_type = %q, want ErrorIndication for a cross-association handover (TS 36.413 §10.6)\n  body: %s", got, ei)
	}

	// The victim is untouched: it can still be released normally on its own eNB.
	if got := jsonGet(nasStep(t, victimENB, victimUE, "release_request"), "s1ap.message_type"); got != "UEContextReleaseCommand" {
		t.Errorf("the victim UE was disturbed by the rogue handover; a normal release did not yield a UEContextReleaseCommand")
	}
}
