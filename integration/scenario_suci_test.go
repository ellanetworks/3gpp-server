// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// SUCI concealment (TS 33.501 §6.12.2, Annex C): when the home network has
// provisioned an ECIES public key, the UE conceals its SUPI in the SUCI under
// Profile A (X25519) or Profile B (P-256). The core's SIDF must de-conceal it to
// recover the SUPI and authenticate the subscriber. These tests register UEs
// whose SUCI is concealed with the public key matching a key the core holds; a
// failure means the core cannot de-conceal a scheme it has provisioned support
// for, i.e. it is not compliant.

package integration_test

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"testing"
)

// deriveX25519PubHex returns the hex X25519 public key (32 bytes) for a hex
// private key.
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

// deriveP256CompressedPubHex returns the hex compressed P-256 public key (33
// bytes, 0x02/0x03 prefix) for a hex private key — the form an operator
// publishes and the core returns.
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

// mustCreateUEProfile creates a UE whose SUCI is concealed with the given
// protection scheme, public key id, and public key.
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

// assertConcealedRegistration runs a full registration. The Authentication
// Request on the first step proves the core de-concealed the SUCI to a known
// SUPI (an undecodable SUCI would be rejected instead); the remaining steps then
// complete the registration.
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

// TestRegistrationSUCIProfileA registers a UE whose SUPI is concealed under
// ECIES Profile A (X25519) with the public key matching the core's provisioned
// Profile A key. The core must de-conceal it and register the subscriber.
func TestRegistrationSUCIProfileA(t *testing.T) {
	gnbID := mustCreateGnB(t)
	pubKey := deriveX25519PubHex(t, profileAPrivKey)

	ueID := mustCreateUEProfile(t, gnbID, "imsi-001010000000024", "1", fmt.Sprintf("%d", profileAKeyID), pubKey)
	assertConcealedRegistration(t, gnbID, ueID)
}

// TestRegistrationSUCIProfileB registers a UE whose SUPI is concealed under
// ECIES Profile B (P-256), with the public key in compressed form (as published
// by the core). The core must de-conceal it and register the subscriber.
func TestRegistrationSUCIProfileB(t *testing.T) {
	gnbID := mustCreateGnB(t)
	pubKey := deriveP256CompressedPubHex(t, profileBPrivKey)

	ueID := mustCreateUEProfile(t, gnbID, "imsi-001010000000025", "2", fmt.Sprintf("%d", profileBKeyID), pubKey)
	assertConcealedRegistration(t, gnbID, ueID)
}
