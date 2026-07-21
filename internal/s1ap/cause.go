// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

// Each value indexes the ASN.1 enumeration named beside it, within its Cause CHOICE group only (TS 36.413 §9.2.1.3).
const (
	CauseRadioNetworkHandoverCancelled               int64 = 4  // handover-cancelled
	CauseRadioNetworkHOFailureInTarget               int64 = 6  // ho-failure-in-target-EPC-eNB-or-target-system
	CauseRadioNetworkHandoverDesirableForRadioReason int64 = 16 // handover-desirable-for-radio-reason
	CauseRadioNetworkUserInactivity                  int64 = 20 // user-inactivity

	CauseMiscOMIntervention int64 = 3 // om-intervention
)
