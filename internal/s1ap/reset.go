// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import "github.com/ellanetworks/core/s1ap"

type ResetConnection struct {
	MMEUES1APID uint32
	ENBUES1APID uint32
}

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
