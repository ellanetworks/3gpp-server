// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// NGResetConnection identifies a UE-associated logical NG-connection to reset
// (TS 38.413 §9.2.6.6). At least one of the AMF/RAN UE NGAP IDs is set.
type NGResetConnection struct {
	AmfUeNgapID *int64
	RanUeNgapID *int64
}

// BuildNGReset builds an NG RESET (TS 38.413 §8.7.4) initiated by the NG-RAN
// node. With no connections it resets the whole NG interface; otherwise it
// resets the listed UE-associated logical NG-connections (partOfNG-Interface).
func BuildNGReset(connections []NGResetConnection) ([]byte, error) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeNGReset
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentNGReset
	im.Value.NGReset = new(ngapType.NGReset)

	ies := &im.Value.NGReset.ProtocolIEs

	causeIE := ngapType.NGResetIEs{}
	causeIE.Id.Value = ngapType.ProtocolIEIDCause
	causeIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	causeIE.Value.Present = ngapType.NGResetIEsPresentCause
	causeIE.Value.Cause = &ngapType.Cause{
		Present: ngapType.CausePresentMisc,
		Misc:    &ngapType.CauseMisc{Value: aper.Enumerated(CauseMiscOMIntervention)},
	}
	ies.List = append(ies.List, causeIE)

	rtIE := ngapType.NGResetIEs{}
	rtIE.Id.Value = ngapType.ProtocolIEIDResetType
	rtIE.Criticality.Value = ngapType.CriticalityPresentReject
	rtIE.Value.Present = ngapType.NGResetIEsPresentResetType
	rtIE.Value.ResetType = new(ngapType.ResetType)

	if len(connections) == 0 {
		rtIE.Value.ResetType.Present = ngapType.ResetTypePresentNGInterface
		rtIE.Value.ResetType.NGInterface = &ngapType.ResetAll{Value: ngapType.ResetAllPresentResetAll}
	} else {
		rtIE.Value.ResetType.Present = ngapType.ResetTypePresentPartOfNGInterface
		list := new(ngapType.UEAssociatedLogicalNGConnectionList)

		for _, c := range connections {
			item := ngapType.UEAssociatedLogicalNGConnectionItem{}
			if c.AmfUeNgapID != nil {
				item.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: *c.AmfUeNgapID}
			}

			if c.RanUeNgapID != nil {
				item.RANUENGAPID = &ngapType.RANUENGAPID{Value: *c.RanUeNgapID}
			}

			list.List = append(list.List, item)
		}

		rtIE.Value.ResetType.PartOfNGInterface = list
	}

	ies.List = append(ies.List, rtIE)

	return ngap.Encoder(pdu)
}
