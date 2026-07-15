// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import "github.com/ellanetworks/core/s1ap"

// ResetConnection identifies one UE-associated logical S1 connection for a
// partial reset, by its UE S1AP ID pair (TS 36.413 §9.2.3.20).
type ResetConnection struct {
	MMEUES1APID uint32
	ENBUES1APID uint32
}

// BuildReset builds an eNB-initiated S1 RESET (TS 36.413 §8.7.1.1). With all set,
// it resets the whole S1 interface; otherwise it resets only the listed
// UE-associated logical connections (partOfS1-Interface).
func BuildReset(all bool, connections []ResetConnection) ([]byte, error) {
	rt := s1ap.ResetType{All: all}

	if !all {
		for _, c := range connections {
			mme := s1ap.MMEUES1APID(c.MMEUES1APID)
			enb := s1ap.ENBUES1APID(c.ENBUES1APID)
			rt.Part = append(rt.Part, s1ap.UEAssociatedLogicalS1ConnectionItem{
				MMEUES1APID: &mme,
				ENBUES1APID: &enb,
			})
		}
	}

	m := &s1ap.Reset{
		Cause:     s1ap.Cause{Group: s1ap.CauseGroupMisc, Value: CauseMiscOMIntervention},
		ResetType: rt,
	}

	return m.Marshal()
}
