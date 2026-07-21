// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import "github.com/free5gc/ngap/ngapType"

const (
	CauseRadioNetworkHandoverDesirableForRadioReason int64 = int64(ngapType.CauseRadioNetworkPresentHandoverDesirableForRadioReason)
	CauseRadioNetworkHandoverCancelled               int64 = int64(ngapType.CauseRadioNetworkPresentHandoverCancelled)
	CauseRadioNetworkHOFailureInTarget               int64 = int64(ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)
	CauseRadioNetworkRadioResourcesNotAvailable      int64 = int64(ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable)
	CauseRadioNetworkUserInactivity                  int64 = int64(ngapType.CauseRadioNetworkPresentUserInactivity)

	CauseMiscOMIntervention int64 = int64(ngapType.CauseMiscPresentOmIntervention)
)
