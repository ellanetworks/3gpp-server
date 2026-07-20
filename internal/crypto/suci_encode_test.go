// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import "testing"

func TestParseSUPI(t *testing.T) {
	mcc, mnc, msin, err := ParseSUPI("imsi-001010000000001", 2)
	if err != nil {
		t.Fatalf("ParseSUPI: %v", err)
	}

	if mcc != "001" || mnc != "01" || msin != "0000000001" {
		t.Fatalf("ParseSUPI = %s/%s/%s, want 001/01/0000000001", mcc, mnc, msin)
	}
}

func TestEncodeSuciNullScheme(t *testing.T) {
	hnPubKey := HomeNetworkPublicKey{ProtectionScheme: NullScheme, PublicKeyID: "0"}

	buffer, err := EncodeSuci("0000000001", "001", "01", "0", hnPubKey)
	if err != nil {
		t.Fatalf("EncodeSuci: %v", err)
	}

	want := mustHex(t, "0100f110f0ff00000000000010")
	if string(buffer) != string(want) {
		t.Fatalf("EncodeSuci buffer = %x, want %x", buffer, want)
	}

	suciStr := BuildSuciString("001", "01", "0", "0", "0", buffer)
	const wantStr = "suci-0-001-01-0-0-0-0000000010"
	if suciStr != wantStr {
		t.Fatalf("BuildSuciString = %s, want %s", suciStr, wantStr)
	}
}

func TestDeriveSNN(t *testing.T) {
	if got := DeriveSNN("001", "01"); got != "5G:mnc001.mcc001.3gppnetwork.org" {
		t.Fatalf("DeriveSNN(001,01) = %s", got)
	}
	if got := DeriveSNN("208", "093"); got != "5G:mnc093.mcc208.3gppnetwork.org" {
		t.Fatalf("DeriveSNN(208,093) = %s", got)
	}
}
