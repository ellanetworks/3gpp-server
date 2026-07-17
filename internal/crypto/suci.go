// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
)

const (
	PrefixSUCI     = "suci"
	SupiTypeIMSI   = "0"
	NullScheme     = "0"
	ProfileAScheme = "1"
	ProfileBScheme = "2"

	profileAMacKeyLen = 32
	profileAEncKeyLen = 16
	profileAIcbLen    = 16
	profileAMacLen    = 8
	profileAHashLen   = 32

	profileBMacKeyLen = 32
	profileBEncKeyLen = 16
	profileBIcbLen    = 16
	profileBMacLen    = 8
	profileBHashLen   = 32
)

type HomeNetworkPublicKey struct {
	ProtectionScheme string
	PublicKey        *ecdh.PublicKey // nil for NullScheme
	PublicKeyID      string
}

// Mcc and Mnc are empty unless SupiType is SupiTypeIMSI.
type Suci struct {
	SupiType         string
	Mcc              string
	Mnc              string
	RoutingIndicator string
	ProtectionScheme string
	PublicKeyID      string
	SchemeOutput     string
	Raw              string
}

var suciRegex = regexp.MustCompile(
	`^suci-(?P<supi_type>(?P<imsiType>0-(?P<mcc>\d{3})-(?P<mnc>\d{2,3}))|(?P<naiType>1-.*))-(?P<routing_indicator>\d{1,4})-(?P<protection_scheme_id>[0-2])-(?P<public_key_id>(?:\d{1,2}|1\d{2}|2[0-4]\d|25[0-5]))-(?P<scheme_output>[A-Fa-f0-9]+)$`,
)

func ParseSuci(input string) *Suci {
	matches := suciRegex.FindStringSubmatch(input)
	if matches == nil {
		return nil
	}

	return &Suci{
		SupiType:         matches[1],
		Mcc:              matches[3],
		Mnc:              matches[4],
		RoutingIndicator: matches[6],
		ProtectionScheme: matches[7],
		PublicKeyID:      matches[8],
		SchemeOutput:     matches[9],
		Raw:              input,
	}
}

// TS 24.501 §9.11.3.4
func Tbcd(value string) string {
	valueBytes := []byte(value)
	for (len(valueBytes) % 2) != 0 {
		valueBytes = append(valueBytes, 'F')
	}

	for i := 1; i < len(valueBytes); i += 2 {
		valueBytes[i-1], valueBytes[i] = valueBytes[i], valueBytes[i-1]
	}

	i := len(valueBytes) - 1
	if valueBytes[i] == 'F' || valueBytes[i] == 'f' {
		valueBytes = valueBytes[:i]
	}

	return string(valueBytes)
}

func CipherSuci(msin, mcc, mnc, routingIndicator string, profile HomeNetworkPublicKey) (*Suci, error) {
	if len(msin)+len(mcc)+len(mnc) < 14 {
		return nil, fmt.Errorf("supi length must be 15")
	}

	var schemeOutput string
	var err error

	switch profile.ProtectionScheme {
	case NullScheme:
		schemeOutput = msin
	case ProfileAScheme:
		schemeOutput, err = profileAEncrypt(msin, profile.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("profile A encryption failed: %w", err)
		}
	case ProfileBScheme:
		schemeOutput, err = profileBEncrypt(msin, profile.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("profile B encryption failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported protection scheme: %s", profile.ProtectionScheme)
	}

	suci := fmt.Sprintf("%s-%s-%s-%s-%s-%s-%s-%s",
		PrefixSUCI,
		SupiTypeIMSI,
		mcc,
		mnc,
		routingIndicator,
		profile.ProtectionScheme,
		profile.PublicKeyID,
		schemeOutput,
	)

	return ParseSuci(suci), nil
}

func profileAEncrypt(msin string, hnPubkey *ecdh.PublicKey) (string, error) {
	x25519Curve := ecdh.X25519()

	ephemeralPriv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral X25519 key: %w", err)
	}

	ephemeralPub := ephemeralPriv.PublicKey().Bytes()

	sharedKey, err := ephemeralPriv.ECDH(hnPubkey)
	if err != nil {
		return "", fmt.Errorf("failed to compute ECDH: %w", err)
	}

	plainBCD, err := hex.DecodeString(Tbcd(msin))
	if err != nil {
		return "", err
	}

	kdfKey := ansiX963KDF(sharedKey, ephemeralPub, profileAEncKeyLen, profileAMacKeyLen, profileAHashLen)
	encKey := kdfKey[:profileAEncKeyLen]
	iv := kdfKey[profileAEncKeyLen : profileAEncKeyLen+profileAIcbLen]
	macKey := kdfKey[len(kdfKey)-profileAMacKeyLen:]

	cipherText, err := aes128ctr(plainBCD, encKey, iv)
	if err != nil {
		return "", err
	}

	mac, err := hmacSha256(cipherText, macKey, profileAMacLen)
	if err != nil {
		return "", err
	}

	out := make([]byte, 0, len(ephemeralPub)+len(cipherText)+len(mac))
	out = append(out, ephemeralPub...)
	out = append(out, cipherText...)
	out = append(out, mac...)

	return hex.EncodeToString(out), nil
}

func profileBEncrypt(msin string, hnPubkey *ecdh.PublicKey) (string, error) {
	p256Curve := ecdh.P256()

	ephemeralPriv, err := p256Curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral P256 key: %w", err)
	}

	sharedKey, err := ephemeralPriv.ECDH(hnPubkey)
	if err != nil {
		return "", fmt.Errorf("failed to compute ECDH: %w", err)
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), ephemeralPriv.PublicKey().Bytes()) //nolint:staticcheck
	if x == nil || y == nil {
		return "", fmt.Errorf("failed to unmarshal ephemeral public key")
	}

	ephemeralPubCompressed := elliptic.MarshalCompressed(elliptic.P256(), x, y)

	plainBCD, err := hex.DecodeString(Tbcd(msin))
	if err != nil {
		return "", err
	}

	kdfKey := ansiX963KDF(sharedKey, ephemeralPubCompressed, profileBEncKeyLen, profileBMacKeyLen, profileBHashLen)
	encKey := kdfKey[:profileBEncKeyLen]
	iv := kdfKey[profileBEncKeyLen : profileBEncKeyLen+profileBIcbLen]
	macKey := kdfKey[len(kdfKey)-profileBMacKeyLen:]

	cipherText, err := aes128ctr(plainBCD, encKey, iv)
	if err != nil {
		return "", err
	}

	mac, err := hmacSha256(cipherText, macKey, profileBMacLen)
	if err != nil {
		return "", err
	}

	out := make([]byte, 0, len(ephemeralPubCompressed)+len(cipherText)+len(mac))
	out = append(out, ephemeralPubCompressed...)
	out = append(out, cipherText...)
	out = append(out, mac...)

	return hex.EncodeToString(out), nil
}

func hmacSha256(input, macKey []byte, macLen int) ([]byte, error) {
	h := hmac.New(sha256.New, macKey)
	if _, err := h.Write(input); err != nil {
		return nil, fmt.Errorf("HMAC SHA256 error: %w", err)
	}
	macVal := h.Sum(nil)
	return macVal[:macLen], nil
}

func aes128ctr(input, encKey, icb []byte) ([]byte, error) {
	output := make([]byte, len(input))
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("AES128 CTR error: %w", err)
	}
	stream := cipher.NewCTR(block, icb)
	stream.XORKeyStream(output, input)
	return output, nil
}

type ECDHPublicKey = ecdh.PublicKey

func ParseX25519PublicKey(raw []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(raw)
}

func ParseP256PublicKey(raw []byte) (*ecdh.PublicKey, error) {
	if len(raw) == 33 && (raw[0] == 0x02 || raw[0] == 0x03) {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw)
		if x == nil {
			return nil, fmt.Errorf("invalid compressed P-256 public key")
		}

		raw = elliptic.Marshal(elliptic.P256(), x, y) //nolint:staticcheck // crypto/ecdh has no compressed-point API
	}

	return ecdh.P256().NewPublicKey(raw)
}

func ansiX963KDF(sharedKey, publicKey []byte, encKeyLen, macKeyLen, hashLen int) []byte {
	var counter uint32 = 1
	var kdfKey []byte
	kdfRounds := int(math.Ceil(float64(encKeyLen+macKeyLen) / float64(hashLen)))
	for i := 0; i < kdfRounds; i++ {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		input := make([]byte, 0, len(sharedKey)+len(counterBytes)+len(publicKey))
		input = append(input, sharedKey...)
		input = append(input, counterBytes...)
		input = append(input, publicKey...)
		tmpK := sha256.Sum256(input)
		kdfKey = append(kdfKey, tmpK[:]...)
		counter++
	}
	return kdfKey
}
