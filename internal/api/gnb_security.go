// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/hex"
	"fmt"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/ellanetworks/3gpp-server/internal/nas5gs"
	"github.com/ellanetworks/3gpp-server/internal/store"
	gonas "github.com/free5gc/nas"
)

// encodeGNBUplinkNAS wraps a plain 5GS NAS message with the UE's security context, advancing the
// UL NAS COUNT and applying any negative-test overrides when req is non-nil (TS 24.501 §4.4).
func encodeGNBUplinkNAS(ue *store.UEContext, plain []byte, sht uint8, req *SendGNBUENGAPRequest) ([]byte, error) {
	if !ue.SecurityActive && len(ue.Kamf) == 0 {
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

	protected, err := nas5gs.Protect(plain, sht, count, ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
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
func decodeGNBDownlinkNAS(ue *store.UEContext, message []byte) (*nas5gs.NASResponse, *bool) {
	sht, err := nas5gs.SecurityHeader(message)
	if err != nil {
		return nil, nil
	}

	if sht == gonas.SecurityHeaderTypePlainNas {
		resp, _ := nas5gs.Decode(message)
		return resp, nil
	}

	if len(message) < 7 {
		return nil, nil
	}

	count := ue.NextDL(message[6])

	newContext := sht == gonas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext ||
		sht == gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext
	if newContext {
		if inner, perr := nas5gs.PeekProtectedPayload(message); perr == nil {
			if smc, derr := nas5gs.Decode(inner); derr == nil {
				establishGNBSecurityContext(ue, smc)
			}
		}
	}

	if !ue.SecurityActive {
		inner, perr := nas5gs.PeekProtectedPayload(message)
		if perr != nil {
			return nil, nil
		}

		resp, _ := nas5gs.Decode(inner)

		return annotateGNBSecurityHeaderType(resp, sht, message), nil
	}

	plain, verr := nas5gs.Unprotect(message, count, ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if plain == nil {
		return nil, nil
	}

	verified := verr == nil
	resp, _ := nas5gs.Decode(plain)

	return annotateGNBSecurityHeaderType(resp, sht, message), &verified
}

func establishGNBSecurityContext(ue *store.UEContext, smc *nas5gs.NASResponse) {
	if smc == nil || smc.SelectedCipheringAlgorithm == nil || smc.SelectedIntegrityAlgorithm == nil {
		return
	}

	ue.CipheringAlg = uint8(*smc.SelectedCipheringAlgorithm)
	ue.IntegrityAlg = uint8(*smc.SelectedIntegrityAlgorithm)

	knasEnc, knasInt, err := crypto.Derive5GNASKeys(ue.Kamf, ue.CipheringAlg, ue.IntegrityAlg)
	if err != nil {
		return
	}

	ue.KnasEnc = knasEnc
	ue.KnasInt = knasInt
	ue.DLCount = 0
	ue.SecurityActive = true
}

func annotateGNBSecurityHeaderType(resp *nas5gs.NASResponse, sht uint8, message []byte) *nas5gs.NASResponse {
	if resp == nil {
		return nil
	}

	resp.SecurityHeaderType = nas5gs.SecurityHeaderTypeString(sht)
	resp.RawHex = hex.EncodeToString(message)

	return resp
}
