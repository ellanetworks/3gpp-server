// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// x963KDF is the ANSI-X9.63 KDF of TS 33.501 §C.3.4.1: for counter = 1, 2, …
// it hashes Z ‖ counter(4-octet big-endian) ‖ SharedInfo and concatenates full
// hash blocks. Reimplemented here, independent of ansiX963KDF, so the test
// validates that derivation rather than mirror it.
func x963KDF(t *testing.T, z, sharedInfo []byte, minLen int) []byte {
	t.Helper()

	var out []byte
	for counter := uint32(1); len(out) < minLen; counter++ {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)

		block := sha256.Sum256(bytes.Join([][]byte{z, c[:], sharedInfo}, nil))
		out = append(out, block[:]...)
	}

	return out
}

func TestAnsiX963KDF(t *testing.T) {
	z := mustHex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	sharedInfo := mustHex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

	got := ansiX963KDF(z, sharedInfo, profileAEncKeyLen, profileAMacKeyLen, profileAHashLen)
	want := x963KDF(t, z, sharedInfo, profileAEncKeyLen+profileAMacKeyLen)

	if !bytes.Equal(got, want) {
		t.Errorf("ansiX963KDF = %x, want %x (TS 33.501 §C.3.4.1)", got, want)
	}
}

// The null-scheme SUCI carries the MSIN in the clear (TS 23.003 §2.2B), so its
// encoding is deterministic.
func TestCipherSuciNullScheme(t *testing.T) {
	profile := HomeNetworkPublicKey{ProtectionScheme: NullScheme, PublicKeyID: "0"}

	suci, err := CipherSuci("0000000001", "001", "01", "0", profile)
	if err != nil {
		t.Fatalf("CipherSuci: %v", err)
	}

	const want = "suci-0-001-01-0-0-0-0000000001"
	if suci.Raw != want {
		t.Fatalf("SUCI = %s, want %s", suci.Raw, want)
	}

	if suci.SchemeOutput != "0000000001" {
		t.Errorf("SchemeOutput = %s, want 0000000001", suci.SchemeOutput)
	}
}

// Profile A (X25519 ECIES, TS 33.501 §C.3.4.2) uses a fresh random ephemeral key
// per call, so Annex C's fixed-key vector cannot be reproduced. This exercises
// the scheme end-to-end: encrypt with the home-network public key, then recover
// the MSIN with the matching private key.
func TestProfileAEncryptRoundTrip(t *testing.T) {
	const msin = "0000000001"

	hnPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate HN key: %v", err)
	}

	ctHex, err := profileAEncrypt(msin, hnPriv.PublicKey())
	if err != nil {
		t.Fatalf("profileAEncrypt: %v", err)
	}

	raw := mustHex(t, ctHex)
	const ephLen = 32

	ephPub, cipherText, mac := splitScheme(t, raw, ephLen, profileAMacLen)

	ephKey, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		t.Fatalf("parse ephemeral key: %v", err)
	}

	shared, err := hnPriv.ECDH(ephKey)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	assertSchemeDecrypts(t, shared, ephPub, cipherText, mac, msin,
		profileAEncKeyLen, profileAIcbLen, profileAMacKeyLen, profileAMacLen)
}

// Profile B (P-256 ECIES, TS 33.501 §C.3.4.3); round-trip for the same reason as
// profile A. The ephemeral key is embedded in compressed SEC1 form.
func TestProfileBEncryptRoundTrip(t *testing.T) {
	const msin = "0000000001"

	hnPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate HN key: %v", err)
	}

	ctHex, err := profileBEncrypt(msin, hnPriv.PublicKey())
	if err != nil {
		t.Fatalf("profileBEncrypt: %v", err)
	}

	raw := mustHex(t, ctHex)
	const ephLen = 33

	ephPub, cipherText, mac := splitScheme(t, raw, ephLen, profileBMacLen)

	ephKey, err := ParseP256PublicKey(ephPub)
	if err != nil {
		t.Fatalf("parse ephemeral key: %v", err)
	}

	shared, err := hnPriv.ECDH(ephKey)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	assertSchemeDecrypts(t, shared, ephPub, cipherText, mac, msin,
		profileBEncKeyLen, profileBIcbLen, profileBMacKeyLen, profileBMacLen)
}

func splitScheme(t *testing.T, raw []byte, ephLen, macLen int) (ephPub, cipherText, mac []byte) {
	t.Helper()

	if len(raw) < ephLen+macLen {
		t.Fatalf("scheme output too short: %d octets", len(raw))
	}

	return raw[:ephLen], raw[ephLen : len(raw)-macLen], raw[len(raw)-macLen:]
}

func assertSchemeDecrypts(t *testing.T, shared, ephPub, cipherText, mac []byte, msin string,
	encKeyLen, icbLen, macKeyLen, macLen int,
) {
	t.Helper()

	kdfKey := x963KDF(t, shared, ephPub, encKeyLen+macKeyLen)
	encKey := kdfKey[:encKeyLen]
	iv := kdfKey[encKeyLen : encKeyLen+icbLen]
	macKey := kdfKey[len(kdfKey)-macKeyLen:]

	h := hmac.New(sha256.New, macKey)
	h.Write(cipherText)
	if wantMac := h.Sum(nil)[:macLen]; !bytes.Equal(mac, wantMac) {
		t.Fatalf("MAC = %x, want %x", mac, wantMac)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatalf("AES cipher: %v", err)
	}

	plain := make([]byte, len(cipherText))
	cipher.NewCTR(block, iv).XORKeyStream(plain, cipherText)

	if want := mustHex(t, Tbcd(msin)); !bytes.Equal(plain, want) {
		t.Fatalf("decrypted BCD = %x, want %x", plain, want)
	}
}
