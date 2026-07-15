// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package ngap

import (
	"testing"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func encodeNGSetupFailureWithTimeToWait(t *testing.T, ttw aper.Enumerated) []byte {
	t.Helper()

	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentUnsuccessfulOutcome
	pdu.UnsuccessfulOutcome = new(ngapType.UnsuccessfulOutcome)

	uo := pdu.UnsuccessfulOutcome
	uo.ProcedureCode.Value = ngapType.ProcedureCodeNGSetup
	uo.Criticality.Value = ngapType.CriticalityPresentReject
	uo.Value.Present = ngapType.UnsuccessfulOutcomePresentNGSetupFailure
	uo.Value.NGSetupFailure = new(ngapType.NGSetupFailure)

	ies := &uo.Value.NGSetupFailure.ProtocolIEs

	cause := ngapType.NGSetupFailureIEs{}
	cause.Id.Value = ngapType.ProtocolIEIDCause
	cause.Criticality.Value = ngapType.CriticalityPresentIgnore
	cause.Value.Present = ngapType.NGSetupFailureIEsPresentCause
	cause.Value.Cause = &ngapType.Cause{
		Present: ngapType.CausePresentMisc,
		Misc:    &ngapType.CauseMisc{Value: ngapType.CauseMiscPresentUnspecified},
	}
	ies.List = append(ies.List, cause)

	wait := ngapType.NGSetupFailureIEs{}
	wait.Id.Value = ngapType.ProtocolIEIDTimeToWait
	wait.Criticality.Value = ngapType.CriticalityPresentIgnore
	wait.Value.Present = ngapType.NGSetupFailureIEsPresentTimeToWait
	wait.Value.TimeToWait = &ngapType.TimeToWait{Value: ttw}
	ies.List = append(ies.List, wait)

	data, err := ngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode NGSetupFailure: %v", err)
	}

	return data
}

func TestDecodeTimeToWaitNames(t *testing.T) {
	cases := map[aper.Enumerated]string{
		ngapType.TimeToWaitPresentV1s:  "v1s",
		ngapType.TimeToWaitPresentV2s:  "v2s",
		ngapType.TimeToWaitPresentV5s:  "v5s",
		ngapType.TimeToWaitPresentV10s: "v10s",
		ngapType.TimeToWaitPresentV20s: "v20s",
		ngapType.TimeToWaitPresentV60s: "v60s",
	}

	for enum, want := range cases {
		data := encodeNGSetupFailureWithTimeToWait(t, enum)

		resp, err := Decode(data)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}

		var got *string
		for i := range resp.IEs {
			if resp.IEs[i].ID == ngapType.ProtocolIEIDTimeToWait {
				got = resp.IEs[i].TimeToWait
			}
		}

		if got == nil {
			t.Fatalf("TimeToWait enum %d: expected name %q, got no TimeToWait IE", enum, want)
		}
		if *got != want {
			t.Errorf("TimeToWait enum %d: expected name %q, got %q", enum, want, *got)
		}
	}
}

func TestDecodeUEContextReleaseCommandBareAMFID(t *testing.T) {
	const amfID int64 = 4242

	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	im := pdu.InitiatingMessage
	im.ProcedureCode.Value = ngapType.ProcedureCodeUEContextRelease
	im.Criticality.Value = ngapType.CriticalityPresentReject
	im.Value.Present = ngapType.InitiatingMessagePresentUEContextReleaseCommand
	im.Value.UEContextReleaseCommand = new(ngapType.UEContextReleaseCommand)

	ies := &im.Value.UEContextReleaseCommand.ProtocolIEs

	ids := ngapType.UEContextReleaseCommandIEs{}
	ids.Id.Value = ngapType.ProtocolIEIDUENGAPIDs
	ids.Criticality.Value = ngapType.CriticalityPresentReject
	ids.Value.Present = ngapType.UEContextReleaseCommandIEsPresentUENGAPIDs
	ids.Value.UENGAPIDs = &ngapType.UENGAPIDs{
		Present:     ngapType.UENGAPIDsPresentAMFUENGAPID,
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
	}
	ies.List = append(ies.List, ids)

	cause := ngapType.UEContextReleaseCommandIEs{}
	cause.Id.Value = ngapType.ProtocolIEIDCause
	cause.Criticality.Value = ngapType.CriticalityPresentIgnore
	cause.Value.Present = ngapType.UEContextReleaseCommandIEsPresentCause
	cause.Value.Cause = &ngapType.Cause{
		Present: ngapType.CausePresentNas,
		Nas:     &ngapType.CauseNas{Value: ngapType.CauseNasPresentNormalRelease},
	}
	ies.List = append(ies.List, cause)

	data, err := ngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("encode UEContextReleaseCommand: %v", err)
	}

	resp, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	var idsIE *IE
	for i := range resp.IEs {
		if resp.IEs[i].ID == ngapType.ProtocolIEIDUENGAPIDs {
			idsIE = &resp.IEs[i]
		}
	}

	if idsIE == nil {
		t.Fatal("expected a UE-NGAP-IDs IE, got none")
	}
	if idsIE.AmfUeNgapID == nil {
		t.Fatalf("bare-AMF-ID CHOICE: expected AmfUeNgapID %d, got nil", amfID)
	}
	if *idsIE.AmfUeNgapID != amfID {
		t.Errorf("bare-AMF-ID CHOICE: expected AmfUeNgapID %d, got %d", amfID, *idsIE.AmfUeNgapID)
	}
	if idsIE.RanUeNgapID != nil {
		t.Errorf("bare-AMF-ID CHOICE: expected no RanUeNgapID, got %d", *idsIE.RanUeNgapID)
	}
}
