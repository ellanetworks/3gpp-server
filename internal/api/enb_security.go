// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"fmt"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

// encodeENBUplinkNAS wraps a plain EPS NAS message with the UE's security context, advancing the
// UL NAS COUNT and applying any negative-test overrides when req is non-nil (TS 24.301 §4.4).
func encodeENBUplinkNAS(ue *store.UEEPSContext, plain []byte, sht naseps.SecurityHeaderType, req *SendENBUES1APRequest) ([]byte, error) {
	if !ue.SecurityActive && len(ue.Kasme) == 0 {
		return nil, fmt.Errorf("no security context available")
	}

	count := ue.NextUL()
	if req != nil && req.NASCountOverride != nil {
		count = *req.NASCountOverride
	}

	protected, err := naseps.Protect(plain, sht, count, ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if req != nil && req.CorruptMAC && len(protected) >= 6 {
		// The EPS security header is 1 octet, so the NAS-MAC's first octet is at index 1.
		protected[1] ^= 0xff
	}

	return protected, nil
}

// epsDLSequenceNumber returns the NAS sequence number of a downlink security-protected
// EPS NAS message (TS 24.301 §9.1: 1-octet header, 4-octet MAC, then the sequence number).
func epsDLSequenceNumber(nasBytes []byte) uint8 {
	const snOffset = 5
	if len(nasBytes) <= snOffset {
		return 0
	}

	return nasBytes[snOffset]
}

func annotateENBSecurityHeaderType(nas *naseps.NASResponse, downlink []byte) *naseps.NASResponse {
	if nas == nil {
		return nil
	}

	if sht, err := naseps.SecurityHeader(downlink); err == nil {
		nas.SecurityHeaderType = naseps.SecurityHeaderTypeString(sht)
	}

	return nas
}

// establishENBSecurityContext derives the EPS NAS keys from the algorithms a
// SECURITY MODE COMMAND selects (TS 24.301 §5.4.3) and activates the context.
func establishENBSecurityContext(ue *store.UEEPSContext, smc *naseps.NASResponse) {
	if smc == nil || smc.SelectedCipheringAlgorithm == nil || smc.SelectedIntegrityAlgorithm == nil {
		return
	}

	ue.CipheringAlg = uint8(*smc.SelectedCipheringAlgorithm)
	ue.IntegrityAlg = uint8(*smc.SelectedIntegrityAlgorithm)

	knasEnc, knasInt, err := crypto.DeriveEPSNASKeys(ue.Kasme, ue.CipheringAlg, ue.IntegrityAlg)
	if err != nil {
		return
	}

	ue.KnasEnc = knasEnc
	ue.KnasInt = knasInt
	ue.ULCount = 0
	ue.DLCount = 0
	ue.SecurityActive = true
}

// decodeENBDownlinkNAS decodes a downlink EPS NAS message, deciphering it with
// the UE's security context when protected and reporting whether the MAC
// verified. A SECURITY MODE COMMAND (new-context header) establishes the context
// as a side effect.
func decodeENBDownlinkNAS(ue *store.UEEPSContext, message []byte) (*naseps.NASResponse, *bool) {
	sht, err := naseps.SecurityHeader(message)
	if err != nil {
		return nil, nil
	}

	if sht == naseps.SHTPlain {
		resp, _ := naseps.Decode(message)
		return annotateENBSecurityHeaderType(resp, message), nil
	}

	if len(message) < 6 {
		return nil, nil
	}

	count := ue.NextDL(epsDLSequenceNumber(message))

	newContext := sht == naseps.SHTIntegrityProtectedNewContext || sht == naseps.SHTIntegrityProtectedCipheredNew
	if newContext {
		if inner, perr := naseps.PeekProtectedPayload(message); perr == nil {
			if smc, derr := naseps.Decode(inner); derr == nil {
				establishENBSecurityContext(ue, smc)
			}
		}
	}

	if !ue.SecurityActive {
		inner, perr := naseps.PeekProtectedPayload(message)
		if perr != nil {
			return nil, nil
		}

		resp, _ := naseps.Decode(inner)

		return annotateENBSecurityHeaderType(resp, message), nil
	}

	plain, verr := naseps.Unprotect(message, count, ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if plain == nil {
		return nil, nil
	}

	verified := verr == nil
	resp, _ := naseps.Decode(plain)

	return annotateENBSecurityHeaderType(resp, message), &verified
}
