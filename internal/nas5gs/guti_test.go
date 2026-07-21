// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package nas5gs

import (
	"testing"

	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

func TestGUTI5GStructuredRoundTrip(t *testing.T) {
	orig := nasType.NewGUTI5G(0)
	orig.SetLen(11)
	orig.SetTypeOfIdentity(nasMessage.MobileIdentity5GSType5gGuti)
	orig.SetMCCDigit1(0)
	orig.SetMCCDigit2(0)
	orig.SetMCCDigit3(1)
	orig.SetMNCDigit1(0)
	orig.SetMNCDigit2(1)
	orig.SetMNCDigit3(0x0f) // 2-digit MNC "01"
	orig.SetAMFRegionID(0xca)
	orig.SetAMFSetID(0x3fa)  // 10-bit
	orig.SetAMFPointer(0x2a) // 6-bit
	orig.SetTMSI5G([4]byte{0x01, 0x02, 0x03, 0x04})

	s := guti5GStructured(orig)

	if s.MCC != "001" {
		t.Errorf("MCC = %q, want 001", s.MCC)
	}
	if s.MNC != "01" {
		t.Errorf("MNC = %q, want 01", s.MNC)
	}
	if s.AMFRegionID != 0xca {
		t.Errorf("AMFRegionID = %#x, want 0xca", s.AMFRegionID)
	}
	if s.AMFSetID != 0x3fa {
		t.Errorf("AMFSetID = %#x, want 0x3fa", s.AMFSetID)
	}
	if s.AMFPointer != 0x2a {
		t.Errorf("AMFPointer = %#x, want 0x2a", s.AMFPointer)
	}
	if s.FiveGTMSI != "01020304" {
		t.Errorf("FiveGTMSI = %q, want 01020304", s.FiveGTMSI)
	}

	back := GUTI5GFromStructured(s)
	if back.Octet != orig.Octet {
		t.Errorf("round-trip Octet mismatch:\n got %x\nwant %x", back.Octet, orig.Octet)
	}
}
