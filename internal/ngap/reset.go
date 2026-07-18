// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

type NGResetConnection struct {
	AMFUENGAPID *int64
	RANUENGAPID *int64
}

func BuildNGReset(all bool, connections []NGResetConnection) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeNGReset
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentNGReset
	im.Value.NGReset = new(ngapType.NGReset)

	ies := &im.Value.NGReset.ProtocolIEs

	add := func(id int64, crit aper.Enumerated, present int) *ngapType.NGResetIEsValue {
		ie := ngapType.NGResetIEs{}
		ie.Id.Value = id
		ie.Criticality.Value = crit
		ie.Value.Present = present
		ies.List = append(ies.List, ie)

		return &ies.List[len(ies.List)-1].Value
	}

	add(ngapType.ProtocolIEIDCause, ngapType.CriticalityPresentIgnore,
		ngapType.NGResetIEsPresentCause).Cause = &ngapType.Cause{
		Present: ngapType.CausePresentMisc,
		Misc:    &ngapType.CauseMisc{Value: aper.Enumerated(CauseMiscOMIntervention)},
	}

	resetType := new(ngapType.ResetType)

	if all {
		resetType.Present = ngapType.ResetTypePresentNGInterface
		resetType.NGInterface = &ngapType.ResetAll{Value: ngapType.ResetAllPresentResetAll}
	} else {
		resetType.Present = ngapType.ResetTypePresentPartOfNGInterface
		list := new(ngapType.UEAssociatedLogicalNGConnectionList)

		for _, c := range connections {
			item := ngapType.UEAssociatedLogicalNGConnectionItem{}
			if c.AMFUENGAPID != nil {
				item.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: *c.AMFUENGAPID}
			}

			if c.RANUENGAPID != nil {
				item.RANUENGAPID = &ngapType.RANUENGAPID{Value: *c.RANUENGAPID}
			}

			list.List = append(list.List, item)
		}

		resetType.PartOfNGInterface = list
	}

	add(ngapType.ProtocolIEIDResetType, ngapType.CriticalityPresentReject,
		ngapType.NGResetIEsPresentResetType).ResetType = resetType

	return ngap.Encoder(pdu)
}
