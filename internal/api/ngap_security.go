// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/hex"
	"fmt"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	nasCodec "github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/store"
	gonas "github.com/free5gc/nas"
)

// encodeGNBUplinkNAS wraps a plain 5GS NAS message with the UE's security context, advancing the
// UL NAS COUNT and applying any negative-test overrides when req is non-nil (TS 24.501 §4.4).
func encodeGNBUplinkNAS(ue *store.UEContext, plain []byte, sht uint8, req *SendNGAPRequest) ([]byte, error) {
	if !ue.SecurityContextAvailable && len(ue.Kamf) == 0 {
		return nil, fmt.Errorf("no security context available")
	}

	if sht == gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext ||
		sht == gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext {
		ue.ULCount = 0
		ue.DLCount = 0
	}

	count := ue.NextUL()
	if req != nil && req.NASCountOverride != nil {
		count = *req.NASCountOverride
	}

	protected, err := nasCodec.Protect(plain, sht, count, ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if req != nil && req.CorruptMAC && len(protected) >= 7 {
		// The 5GS security header is 2 octets, so the NAS-MAC's first octet is at index 2.
		protected[2] ^= 0xff
	}

	ue.LastUplinkNAS = protected

	return protected, nil
}

// decodeGNBDownlinkNAS unwraps a downlink 5GS NAS PDU: it advances the DL NAS COUNT, establishes
// the security context from a Security Mode Command, verifies the NAS-MAC, and decodes the plain
// message. It reports whether the downlink was successfully integrity checked (TS 24.501 §4.4.4.2).
func decodeGNBDownlinkNAS(ue *store.UEContext, message []byte) (*nasCodec.NASResponse, *bool) {
	sht, err := nasCodec.SecurityHeader(message)
	if err != nil {
		return nil, nil
	}

	if sht == gonas.SecurityHeaderTypePlainNas {
		resp, _ := nasCodec.Decode(message)
		return resp, nil
	}

	if len(message) < 7 {
		return nil, nil
	}

	count := ue.NextDL(message[6])

	newContext := sht == gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext ||
		sht == gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext
	if newContext {
		if inner, perr := nasCodec.PeekProtectedPayload(message); perr == nil {
			if smc, derr := nasCodec.Decode(inner); derr == nil {
				establishGNBSecurityContext(ue, smc)
			}
		}
	}

	if !ue.SecurityContextAvailable {
		inner, perr := nasCodec.PeekProtectedPayload(message)
		if perr != nil {
			return nil, nil
		}

		resp, _ := nasCodec.Decode(inner)

		return annotateGNBSecurityHeaderType(resp, sht, message), nil
	}

	plain, verr := nasCodec.Unprotect(message, count, ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if plain == nil {
		return nil, nil
	}

	verified := verr == nil
	resp, _ := nasCodec.Decode(plain)

	return annotateGNBSecurityHeaderType(resp, sht, message), &verified
}

func establishGNBSecurityContext(ue *store.UEContext, smc *nasCodec.NASResponse) {
	if smc == nil || smc.SelectedCipheringAlg == nil || smc.SelectedIntegrityAlg == nil {
		return
	}

	ue.CipheringAlg = uint8(*smc.SelectedCipheringAlg)
	ue.IntegrityAlg = uint8(*smc.SelectedIntegrityAlg)

	knasEnc, knasInt, err := crypto.Derive5GNASKeys(ue.Kamf, ue.CipheringAlg, ue.IntegrityAlg)
	if err != nil {
		return
	}

	ue.KnasEnc = knasEnc
	ue.KnasInt = knasInt
	ue.DLCount = 0
	ue.SecurityContextAvailable = true
}

func annotateGNBSecurityHeaderType(resp *nasCodec.NASResponse, sht uint8, message []byte) *nasCodec.NASResponse {
	if resp == nil {
		return nil
	}

	resp.SecurityHeaderType = nasCodec.SecurityHeaderTypeString(sht)
	resp.RawHex = hex.EncodeToString(message)

	return resp
}
