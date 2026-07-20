// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

func erabSGWIP(enb *store.ENBContext, e s1ap.ERABSetupItemJSON) string {
	if a, err := netip.ParseAddr(enb.N3Addr); err == nil && a.Is6() {
		return firstNonEmpty(e.TransportLayerAddressIPv6, e.TransportLayerAddress)
	}

	return firstNonEmpty(e.TransportLayerAddress, e.TransportLayerAddressIPv6)
}

func handleENBPdnConnectivity(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	pti := uint8(5)
	if req.PTI != nil {
		pti = *req.PTI
	}

	pdnType := req.PDNType
	if pdnType == 0 {
		pdnType = naseps.PDNTypeIPv4
	}

	params := naseps.PDNConnectivityParams{PTI: pti, PDNType: pdnType, APN: req.APN}
	if req.RequestEBI != nil {
		params.EPSBearerIdentity = *req.RequestEBI
	}

	esm, err := naseps.BuildPDNConnectivityRequestWith(params)
	if err != nil {
		return nil, err
	}

	protected, err := naseps.Protect(esm, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	dl := waitDownlinkTolerant(ctx, t, ue, "ERABSetupRequest", "DownlinkNASTransport")
	if dl == nil {
		return &SendENBUES1APResponse{}, nil
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(epsDLSequenceNumber(nasBytes)), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, fmt.Errorf("unprotect pdn connectivity reply: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateSecurityHeaderType(nas, nasBytes)

	if dl.MessageType != "ERABSetupRequest" || nas.MessageType != "activate_default_eps_bearer_context_request" {
		return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
	}

	// Withholding the accept leaves timer T3485 running so its retransmission is observable (TS 24.301 §6.4.1.6 a).
	if req.WithholdAccept {
		return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
	}

	if err := acceptAdditionalBearer(enb, ue, t, dl, nas, req); err != nil {
		return nil, err
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

func acceptAdditionalBearer(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, dl *s1ap.S1APResponse, nas *naseps.NASResponse, req *SendENBUES1APRequest) error {
	if nas.EPSBearerIdentity == nil {
		return fmt.Errorf("activate default without an EPS bearer identity")
	}

	ebi := uint8(*nas.EPSBearerIdentity)
	pti := uint8(0)
	if nas.BearerPTI != nil {
		pti = uint8(*nas.BearerPTI)
	}

	bearer := &store.EPSBearer{
		EBI:    ebi,
		PTI:    pti,
		APN:    nas.APN,
		UEIP:   ueIPFromPDNAddress(nas.PDNAddress),
		DLTeid: (ue.ENBUES1APID << 8) | uint32(ebi),
	}

	if len(dl.ERABSetupItems) > 0 {
		e := dl.ERABSetupItems[0]
		bearer.ULTeid = e.GTPTEID
		bearer.SGWIP = erabSGWIP(enb, e)
	}

	ue.Bearers[ebi] = bearer

	erabResp, err := s1ap.BuildERABSetupResponse(s1ap.InitialContextSetupResponseParams{
		MMEUES1APID: ue.MMEUES1APID, ENBUES1APID: ue.ENBUES1APID,
		ERABID: ebi, ENBN3Addr: enb.N3Addr, GTPTEID: bearer.DLTeid,
	})
	if err != nil {
		return err
	}

	if err := t.Send(erabResp, false); err != nil {
		return err
	}

	accept, err := naseps.BuildActivateDefaultEPSBearerContextAccept(ebi, pti)
	if err != nil {
		return err
	}

	protectedAccept, err := naseps.Protect(accept, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return err
	}

	return sendUplink(enb, ue, t, protectedAccept, req)
}

func handleENBPdnDisconnect(ctx context.Context, enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	pti := uint8(6)
	if req.PTI != nil {
		pti = *req.PTI
	}

	linkedEBI := ue.EPSBearerID
	if req.LinkedEBI != nil {
		linkedEBI = *req.LinkedEBI
	}

	esm, err := naseps.BuildPDNDisconnectRequest(pti, linkedEBI)
	if err != nil {
		return nil, err
	}

	protected, err := naseps.Protect(esm, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	dl := waitDownlinkTolerant(ctx, t, ue, "ERABReleaseCommand", "DownlinkNASTransport")
	if dl == nil {
		return &SendENBUES1APResponse{}, nil
	}

	nasBytes, err := nasPDUBytes(dl)
	if err != nil {
		return nil, err
	}

	plain, err := naseps.Unprotect(nasBytes, ue.NextDL(epsDLSequenceNumber(nasBytes)), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, fmt.Errorf("unprotect pdn disconnect reply: %w", err)
	}

	nas, err := naseps.Decode(plain)
	if err != nil {
		return nil, err
	}

	annotateSecurityHeaderType(nas, nasBytes)

	// Withholding the accept leaves timer T3495 running so its retransmission is observable (TS 24.301 §6.4.4.5 a).
	if req.WithholdAccept {
		return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
	}

	if nas.MessageType == "deactivate_eps_bearer_context_request" && nas.EPSBearerIdentity != nil {
		deactEBI := uint8(*nas.EPSBearerIdentity)
		deactPTI := uint8(0)
		if nas.BearerPTI != nil {
			deactPTI = uint8(*nas.BearerPTI)
		}

		// The radio-bearer release must be confirmed before the NAS accept.
		if dl.MessageType == "ERABReleaseCommand" {
			relResp, rerr := s1ap.BuildERABReleaseResponse(ue.MMEUES1APID, ue.ENBUES1APID, deactEBI)
			if rerr != nil {
				return nil, rerr
			}

			if serr := t.Send(relResp, false); serr != nil {
				return nil, serr
			}
		}

		accept, berr := naseps.BuildDeactivateEPSBearerContextAccept(deactEBI, deactPTI)
		if berr != nil {
			return nil, berr
		}

		protectedAccept, perr := naseps.Protect(accept, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
		if perr != nil {
			return nil, perr
		}

		if serr := sendUplink(enb, ue, t, protectedAccept, req); serr != nil {
			return nil, serr
		}

		delete(ue.Bearers, deactEBI)
	}

	return &SendENBUES1APResponse{S1AP: dl, NAS: nas}, nil
}

func handleENBStatusESM(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	cause := esmCauseProtocolErrorUnspec
	if req.ESMCause != nil {
		cause = *req.ESMCause
	}

	esm, err := naseps.BuildESMStatus(esmBearerID(ue, req), esmPTI(req), cause)
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBBearerResourceAllocation(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildBearerResourceAllocationRequest(esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBBearerResourceModification(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildBearerResourceModificationRequest(esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBEsmInformationResponse(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildESMInformationResponse(esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBModifyBearerAccept(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildModifyEPSBearerContextAccept(esmBearerID(ue, req), esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func handleENBDeactivateBearerAccept(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	if !ue.SecurityActive {
		return nil, httpErrorf(http.StatusBadRequest, "no NAS security context; complete an attach first")
	}

	esm, err := naseps.BuildDeactivateEPSBearerContextAccept(esmBearerID(ue, req), esmPTI(req))
	if err != nil {
		return nil, err
	}

	return sendESM(enb, ue, t, esm, req)
}

func sendESM(enb *store.ENBContext, ue *store.UEEPSContext, t *transport.S1APTransport, esm []byte, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	protected, err := naseps.Protect(esm, naseps.SHTIntegrityProtectedCiphered, ue.NextUL(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc, ue.KnasInt)
	if err != nil {
		return nil, err
	}

	if err := sendUplink(enb, ue, t, protected, req); err != nil {
		return nil, err
	}

	return &SendENBUES1APResponse{}, nil
}

func esmBearerID(ue *store.UEEPSContext, req *SendENBUES1APRequest) uint8 {
	if req.EPSBearerIdentity != nil {
		return *req.EPSBearerIdentity
	}

	return ue.EPSBearerID
}

func esmPTI(req *SendENBUES1APRequest) uint8 {
	if req.PTI != nil {
		return *req.PTI
	}

	return 0
}

func handleENBModifyResponse(ue *store.UEEPSContext, t *transport.S1APTransport, req *SendENBUES1APRequest) (*SendENBUES1APResponse, error) {
	encoded, err := s1ap.BuildERABModifyResponse(ue.MMEUES1APID, ue.ENBUES1APID, []uint8{esmBearerID(ue, req)})
	if err != nil {
		return nil, err
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, err
	}

	return &SendENBUES1APResponse{}, nil
}
