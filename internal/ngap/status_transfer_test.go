// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"testing"

	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func TestBuildUplinkRANStatusTransfer(t *testing.T) {
	data, err := BuildUplinkRANStatusTransfer(7, 9, []DRBStatusTransferItem{
		{DRBID: 3, ULPDCPSN: 42, ULHFN: 7, DLPDCPSN: 99, DLHFN: 3},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	pdu, err := ngap.Decoder(data)
	if err != nil {
		t.Fatalf("decode built PDU: %v", err)
	}

	im := pdu.InitiatingMessage
	if im == nil || im.ProcedureCode.Value != ngapType.ProcedureCodeUplinkRANStatusTransfer {
		t.Fatalf("procedure code = %v, want UplinkRANStatusTransfer (%d)", im, ngapType.ProcedureCodeUplinkRANStatusTransfer)
	}

	var (
		amf, ran  *int64
		container *ngapType.RANStatusTransferTransparentContainer
	)

	for _, ie := range im.Value.UplinkRANStatusTransfer.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			amf = &ie.Value.AMFUENGAPID.Value
		case ngapType.ProtocolIEIDRANUENGAPID:
			ran = &ie.Value.RANUENGAPID.Value
		case ngapType.ProtocolIEIDRANStatusTransferTransparentContainer:
			container = ie.Value.RANStatusTransferTransparentContainer
		}
	}

	if amf == nil || *amf != 7 {
		t.Errorf("AMF UE NGAP ID = %v, want 7", amf)
	}

	if ran == nil || *ran != 9 {
		t.Errorf("RAN UE NGAP ID = %v, want 9", ran)
	}

	if container == nil {
		t.Fatal("no RAN Status Transfer Transparent Container (mandatory, TS 38.413 §9.2.3.13)")
	}

	list := container.DRBsSubjectToStatusTransferList.List
	if len(list) != 1 {
		t.Fatalf("DRBs subject to status transfer = %d, want 1", len(list))
	}

	item := list[0]
	if item.DRBID.Value != 3 {
		t.Errorf("drb id = %d, want 3", item.DRBID.Value)
	}

	if item.DRBStatusUL.DRBStatusUL12 == nil {
		t.Fatal("no UL COUNT (mandatory per DRB, TS 38.413 §8.4.6.2)")
	}

	if ul := item.DRBStatusUL.DRBStatusUL12.ULCOUNTValue; ul.PDCPSN12 != 42 || ul.HFNPDCPSN12 != 7 {
		t.Errorf("UL COUNT = {sn:%d hfn:%d}, want {42 7}", ul.PDCPSN12, ul.HFNPDCPSN12)
	}

	if item.DRBStatusDL.DRBStatusDL12 == nil {
		t.Fatal("no DL COUNT (mandatory per DRB, TS 38.413 §8.4.6.2)")
	}

	if dl := item.DRBStatusDL.DRBStatusDL12.DLCOUNTValue; dl.PDCPSN12 != 99 || dl.HFNPDCPSN12 != 3 {
		t.Errorf("DL COUNT = {sn:%d hfn:%d}, want {99 3}", dl.PDCPSN12, dl.HFNPDCPSN12)
	}
}

func TestDecodeDownlinkRANStatusTransfer(t *testing.T) {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeDownlinkRANStatusTransfer
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentDownlinkRANStatusTransfer
	im.Value.DownlinkRANStatusTransfer = new(ngapType.DownlinkRANStatusTransfer)

	ies := &im.Value.DownlinkRANStatusTransfer.ProtocolIEs

	amf := ngapType.DownlinkRANStatusTransferIEs{}
	amf.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amf.Criticality.Value = ngapType.CriticalityPresentReject
	amf.Value.Present = ngapType.DownlinkRANStatusTransferIEsPresentAMFUENGAPID
	amf.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: 11}
	ies.List = append(ies.List, amf)

	ran := ngapType.DownlinkRANStatusTransferIEs{}
	ran.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ran.Criticality.Value = ngapType.CriticalityPresentReject
	ran.Value.Present = ngapType.DownlinkRANStatusTransferIEsPresentRANUENGAPID
	ran.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: 100}
	ies.List = append(ies.List, ran)

	item := ngapType.DRBsSubjectToStatusTransferItem{DRBID: ngapType.DRBID{Value: 3}}
	item.DRBStatusUL.Present = ngapType.DRBStatusULPresentDRBStatusUL12
	item.DRBStatusUL.DRBStatusUL12 = &ngapType.DRBStatusUL12{
		ULCOUNTValue: ngapType.COUNTValueForPDCPSN12{PDCPSN12: 42, HFNPDCPSN12: 7},
	}
	item.DRBStatusDL.Present = ngapType.DRBStatusDLPresentDRBStatusDL12
	item.DRBStatusDL.DRBStatusDL12 = &ngapType.DRBStatusDL12{
		DLCOUNTValue: ngapType.COUNTValueForPDCPSN12{PDCPSN12: 99, HFNPDCPSN12: 3},
	}

	cont := ngapType.DownlinkRANStatusTransferIEs{}
	cont.Id.Value = ngapType.ProtocolIEIDRANStatusTransferTransparentContainer
	cont.Criticality.Value = ngapType.CriticalityPresentReject
	cont.Value.Present = ngapType.DownlinkRANStatusTransferIEsPresentRANStatusTransferTransparentContainer
	cont.Value.RANStatusTransferTransparentContainer = new(ngapType.RANStatusTransferTransparentContainer)
	cont.Value.RANStatusTransferTransparentContainer.DRBsSubjectToStatusTransferList.List = []ngapType.DRBsSubjectToStatusTransferItem{item}
	ies.List = append(ies.List, cont)

	data, err := ngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	resp, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.MessageType != "DownlinkRANStatusTransfer" {
		t.Fatalf("message_type = %q, want DownlinkRANStatusTransfer", resp.MessageType)
	}

	gotAmf, gotRan := resp.AMFUENGAPID, resp.RANUENGAPID
	gotContainer := resp.RANStatusTransfer

	if gotAmf == nil || *gotAmf != 11 {
		t.Errorf("amf_ue_ngap_id = %v, want 11", gotAmf)
	}

	if gotRan == nil || *gotRan != 100 {
		t.Errorf("ran_ue_ngap_id = %v, want 100", gotRan)
	}

	if gotContainer == nil || len(gotContainer.DRBs) != 1 {
		t.Fatalf("ran_status_transfer = %+v, want 1 DRB", gotContainer)
	}

	drb := gotContainer.DRBs[0]
	if drb.DRBID != 3 {
		t.Errorf("drb_id = %d, want 3", drb.DRBID)
	}

	if drb.ULCount == nil || drb.ULCount.PDCPSN != 42 || drb.ULCount.HFN != 7 {
		t.Errorf("ul_count = %+v, want {42 7}", drb.ULCount)
	}

	if drb.DLCount == nil || drb.DLCount.PDCPSN != 99 || drb.DLCount.HFN != 3 {
		t.Errorf("dl_count = %+v, want {99 3}", drb.DLCount)
	}
}
