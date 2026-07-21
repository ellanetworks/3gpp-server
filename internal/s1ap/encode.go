// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package s1ap

import (
	"fmt"

	"github.com/ellanetworks/core/s1ap"
)

func BuildS1SetupRequest(p *S1SetupRequestParams) ([]byte, error) {
	enbPLMN, err := encodePLMN(p.MCC, p.MNC)
	if err != nil {
		return nil, err
	}

	tas, err := buildSupportedTAs(p, enbPLMN)
	if err != nil {
		return nil, err
	}

	drx := s1ap.PagingDRXv128
	if p.DefaultPagingDRX != nil {
		if *p.DefaultPagingDRX < 0 || *p.DefaultPagingDRX > int(s1ap.PagingDRXv256) {
			return nil, fmt.Errorf("default_paging_drx must be 0..3 (v32, v64, v128, v256)")
		}
		drx = s1ap.PagingDRX(*p.DefaultPagingDRX)
	}

	req := &s1ap.S1SetupRequest{
		GlobalENBID: s1ap.GlobalENBID{
			PLMNIdentity: enbPLMN,
			ENBID:        s1ap.ENBID{Kind: p.ENBIDKind, Value: p.ENBID},
		},
		ENBName:          p.ENBName,
		SupportedTAs:     tas,
		DefaultPagingDRX: drx,
	}

	return req.Marshal()
}

func buildSupportedTAs(p *S1SetupRequestParams, enbPLMN s1ap.PLMNIdentity) (s1ap.SupportedTAs, error) {
	if len(p.SupportedTAs) == 0 {
		tac, err := parseTAC(p.TAC)
		if err != nil {
			return nil, err
		}

		return s1ap.SupportedTAs{{TAC: s1ap.TAC(tac), BroadcastPLMNs: s1ap.BPLMNs{enbPLMN}}}, nil
	}

	out := make(s1ap.SupportedTAs, 0, len(p.SupportedTAs))

	for _, ta := range p.SupportedTAs {
		bplmns := s1ap.BPLMNs{}

		if len(ta.BroadcastPLMNs) == 0 {
			bplmns = append(bplmns, enbPLMN)
		}

		for _, pl := range ta.BroadcastPLMNs {
			b, err := encodePLMN(pl.MCC, pl.MNC)
			if err != nil {
				return nil, err
			}

			bplmns = append(bplmns, b)
		}

		tac, err := parseTAC(ta.TAC)
		if err != nil {
			return nil, err
		}

		out = append(out, s1ap.SupportedTAItem{TAC: s1ap.TAC(tac), BroadcastPLMNs: bplmns})
	}

	return out, nil
}
