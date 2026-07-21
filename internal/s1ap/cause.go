// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import "github.com/ellanetworks/core/s1ap"

// radioNetworkCause builds a RadioNetwork Cause, extension-marking values beyond the
// 36 root ENUMERATED values (TS 36.413 §9.2.1.3) so an out-of-range cause still encodes.
func radioNetworkCause(v int64) s1ap.Cause {
	const rootCount = 36
	if v >= rootCount {
		return s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: int(v) - rootCount, Extended: true}
	}

	return s1ap.Cause{Group: s1ap.CauseGroupRadioNetwork, Value: int(v)}
}

// Each value indexes the ASN.1 enumeration named beside it, within its Cause CHOICE group only (TS 36.413 §9.2.1.3).
const (
	CauseRadioNetworkHandoverCancelled               int64 = 4  // handover-cancelled
	CauseRadioNetworkHOFailureInTarget               int64 = 6  // ho-failure-in-target-EPC-eNB-or-target-system
	CauseRadioNetworkHandoverDesirableForRadioReason int64 = 16 // handover-desirable-for-radio-reason
	CauseRadioNetworkUserInactivity                  int64 = 20 // user-inactivity

	CauseMiscOMIntervention int64 = 3 // om-intervention
)
