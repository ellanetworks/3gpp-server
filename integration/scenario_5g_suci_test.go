// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"testing"
)

func deriveX25519PubHex(t *testing.T, privHex string) string {
	t.Helper()

	priv, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("decode X25519 private key: %v", err)
	}

	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("X25519 private key: %v", err)
	}

	return hex.EncodeToString(k.PublicKey().Bytes())
}

func deriveP256CompressedPubHex(t *testing.T, privHex string) string {
	t.Helper()

	priv, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("decode P-256 private key: %v", err)
	}

	k, err := ecdh.P256().NewPrivateKey(priv)
	if err != nil {
		t.Fatalf("P-256 private key: %v", err)
	}

	uncompressed := k.PublicKey().Bytes() // 65 bytes: 0x04 || x(32) || y(32)

	prefix := byte(0x02)
	if uncompressed[64]&1 == 1 {
		prefix = 0x03
	}

	return hex.EncodeToString(append([]byte{prefix}, uncompressed[1:33]...))
}

func mustCreateUEProfile(t *testing.T, gnbID, supi, scheme, keyID, pubKeyHex string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"supi": %q, "k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d", "amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": "internet", "routing_indicator": "0",
		"protection_scheme": %q, "public_key_id": %q, "public_key_hex": %q,
		"imeisv": "1122334455667788"
	}`, supi, scheme, keyID, pubKeyHex)

	return createUEWithBody(t, gnbID, body)
}

func assertConcealedRegistration(t *testing.T, gnbID, ueID string) {
	t.Helper()

	status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"registration_request"}`)
	if status != 200 {
		t.Fatalf("registration_request: HTTP %d\n  body: %s", status, body)
	}

	if got := jsonGet(body, "nas.message_type"); got != nasAuthenticationRequest {
		t.Fatalf("registration_request: nas.message_type = %q, want authentication_request — the core did not de-conceal the SUCI to a known subscriber (TS 33.501 §6.12.2)\n  body: %s", got, body)
	}

	for _, step := range []string{"authentication_response", "security_mode_complete", "registration_complete"} {
		status, body := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
			fmt.Sprintf(`{"message_type":%q}`, step))
		if status != 200 {
			t.Fatalf("%s: HTTP %d\n  body: %s", step, status, body)
		}
	}
}

func Test5GRegistrationSUCIProfileA(t *testing.T) {
	gnbID := mustCreateGnB(t)
	pubKey := deriveX25519PubHex(t, profileAPrivKey)

	ueID := mustCreateUEProfile(t, gnbID, "imsi-001010000000024", "1", fmt.Sprintf("%d", profileAKeyID), pubKey)
	assertConcealedRegistration(t, gnbID, ueID)
}

func Test5GRegistrationSUCIProfileB(t *testing.T) {
	gnbID := mustCreateGnB(t)
	pubKey := deriveP256CompressedPubHex(t, profileBPrivKey)

	ueID := mustCreateUEProfile(t, gnbID, "imsi-001010000000025", "2", fmt.Sprintf("%d", profileBKeyID), pubKey)
	assertConcealedRegistration(t, gnbID, ueID)
}
