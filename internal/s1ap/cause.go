// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

// S1AP Cause values the eNB sends (TS 36.413 §9.2.1.3). A value is scoped to its
// Cause CHOICE group, so each is grouped under the group it belongs to. The
// trailing name is the ASN.1 enumeration the value indexes.
const (
	// radioNetwork group.
	CauseRadioNetworkHandoverCancelled               = 4  // handover-cancelled
	CauseRadioNetworkHOFailureInTarget               = 6  // ho-failure-in-target-EPC-eNB-or-target-system
	CauseRadioNetworkHandoverDesirableForRadioReason = 16 // handover-desirable-for-radio-reason
	CauseRadioNetworkUserInactivity                  = 20 // user-inactivity

	// misc group.
	CauseMiscOMIntervention = 3 // om-intervention
)
