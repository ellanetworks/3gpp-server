// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

// Each value indexes the ASN.1 enumeration named beside it, within its Cause CHOICE group only (TS 36.413 §9.2.1.3).
const (
	CauseRadioNetworkHandoverCancelled               = 4  // handover-cancelled
	CauseRadioNetworkHOFailureInTarget               = 6  // ho-failure-in-target-EPC-eNB-or-target-system
	CauseRadioNetworkHandoverDesirableForRadioReason = 16 // handover-desirable-for-radio-reason
	CauseRadioNetworkUserInactivity                  = 20 // user-inactivity

	CauseMiscOMIntervention = 3 // om-intervention
)
