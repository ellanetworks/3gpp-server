// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/netip"

	"github.com/ellanetworks/3gpp-server/internal/gtpu"
	nasCodec "github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
)

func captureTunnel(gnb *store.GNBContext, ue *store.UEContext, pduSessionID int64, dlTeid uint32, ngapResp *ngap.NGAPResponse, nasResp *nasCodec.NASResponse) {
	info := &store.PDUSessionInfo{
		PDUSessionID: uint8(pduSessionID),
		N3GnbIP:      gnb.N3Addr,
		DLTeid:       dlTeid,
		QFI:          1,
	}

	gnbN3IsV6 := false
	if a, err := netip.ParseAddr(gnb.N3Addr); err == nil {
		gnbN3IsV6 = a.Is6()
	}

	for _, item := range ngapResp.PDUSessionSetupItems {
		if item.PDUSessionID == pduSessionID {
			info.ULTeid = item.ULTeid
			if gnbN3IsV6 {
				info.UPFIP = firstNonEmpty(item.UPFN3IPv6, item.UPFN3IP)
			} else {
				info.UPFIP = firstNonEmpty(item.UPFN3IP, item.UPFN3IPv6)
			}
		}
	}

	if nasResp != nil {
		info.UEIP = nasResp.PDUAddress
	}

	ue.PDUSessions[uint8(pduSessionID)] = info
}

func handleGnBPDUSessionEstablishmentRequest(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, gt *gtpu.Endpoint, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	pduSessionID := ue.PDUSessionID
	if req.PDUSessionIDOverride != nil {
		pduSessionID = *req.PDUSessionIDOverride
	}

	if pduSessionID == 0 {
		pduSessionID = 1
	}

	pduSessionType := ue.PDUSessionType
	if pduSessionType == 0 {
		pduSessionType = 1
	}

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		return sendUplinkAndWait(ctx, gnb, ue, t, req, raw, "PDUSessionResourceSetupRequest", "DownlinkNASTransport", "ErrorIndication")
	}

	var (
		pduReq []byte
		err    error
	)

	if req.InnerSMPayload != nil {
		pduReq, err = hex.DecodeString(*req.InnerSMPayload)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode inner_sm_payload: %v", err)
		}
	} else {
		pduReq, err = nasCodec.BuildPDUSessionEstablishmentRequest(&nasCodec.PDUSessionEstablishmentRequestOpts{
			PDUSessionID:   pduSessionID,
			PDUSessionType: pduSessionType,
			PTI:            ptiFor(req),
			AlwaysOn:       req.AlwaysOnRequested != nil && *req.AlwaysOnRequested,
		})
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionEstablishmentRequest: %v", err)
		}
	}

	ulNas, err := nasCodec.BuildULNASTransport(&nasCodec.ULNASTransportOpts{
		PduSessionID:     pduSessionID,
		PayloadContainer: pduReq,
		DNN:              ue.DNN,
		SST:              ue.SST,
		SD:               ue.SD,
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build ULNASTransport: %v", err)
	}

	securedPDU, err := encodeGNBUplinkNAS(ue, ulNas,
		gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
	}

	encoded, err := ngap.BuildUplinkNASTransport(ngap.UplinkNASTransportParams{
		AMFUENGAPID: ue.AMFUENGAPID,
		RANUENGAPID: ue.RANUENGAPID,
		NASPDU:      securedPDU,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GnbID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"PDUSessionResourceSetupRequest", "DownlinkNASTransport", "ErrorIndication")
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for PDU establishment response: %v", err)
	}

	var nasResp *nasCodec.NASResponse

	var macVerified *bool

	if ngapResp.NasPDU != nil {
		if nasPDUBytes, err := hex.DecodeString(*ngapResp.NasPDU); err == nil {
			nasResp, macVerified = decodeGNBDownlinkNAS(ue, nasPDUBytes)
		}
	}

	if ngapResp.MessageType == "PDUSessionResourceSetupRequest" {
		dlTeid := uint32(ue.RANUENGAPID)<<8 | uint32(pduSessionID)

		pduSetupResp, err := ngap.BuildPDUSessionResourceSetupResponse(ngap.PDUSessionResourceSetupResponseParams{
			AMFUENGAPID:  ue.AMFUENGAPID,
			RANUENGAPID:  ue.RANUENGAPID,
			PDUSessionID: int64(pduSessionID),
			DLTeid:       dlTeid,
			DLIP:         gnb.N3Addr,
		})
		if err == nil {
			_ = t.Send(pduSetupResp, false)
		}

		if gt != nil {
			captureTunnel(gnb, ue, int64(pduSessionID), dlTeid, ngapResp, nasResp)
		}
	}

	return &SendNGAPResponse{
		NGAP:        ngapResp,
		NAS:         nasResp,
		MACVerified: macVerified,
	}, nil
}

func ptiFor(req *SendNGAPRequest) uint8 {
	if req != nil && req.PTIOverride != nil {
		return *req.PTIOverride
	}

	return 0x01
}

func pduSessionIDForRelease(ue *store.UEContext) uint8 {
	if ue.PDUSessionID >= 1 && ue.PDUSessionID <= 15 {
		return ue.PDUSessionID
	}

	return 1
}

func handleGnBPDUSessionReleaseRequest(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		relReq, err := nasCodec.BuildPDUSessionReleaseRequest(pduSessionID, ptiFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionReleaseRequest: %v", err)
		}

		inner = relReq
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build ULNASTransport: %v", err)
	}

	secured, err := encodeGNBUplinkNAS(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, secured, "PDUSessionResourceReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
}

func handleGnBPDUSessionModificationRequest(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		modReq, err := nasCodec.BuildPDUSessionModificationRequest(pduSessionID, ptiFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionModificationRequest: %v", err)
		}

		inner = modReq
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build ULNASTransport: %v", err)
	}

	secured, err := encodeGNBUplinkNAS(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, secured, "PDUSessionResourceModifyRequest", "DownlinkNASTransport", "ErrorIndication")
}

func handleGnBPDUSessionReleaseComplete(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		cmp, err := nasCodec.BuildPDUSessionReleaseComplete(pduSessionID, ptiFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionReleaseComplete: %v", err)
		}

		inner = cmp
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build ULNASTransport: %v", err)
	}

	secured, err := encodeGNBUplinkNAS(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
	}

	encoded, err := ngap.BuildUplinkNASTransport(ngap.UplinkNASTransportParams{
		AMFUENGAPID: ue.AMFUENGAPID,
		RANUENGAPID: ue.RANUENGAPID,
		NASPDU:      secured,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GnbID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendNGAPResponse{}, nil
}

func handleGnBPDUSessionModificationComplete(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		cmp, err := nasCodec.BuildPDUSessionModificationComplete(pduSessionID, ptiFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionModificationComplete: %v", err)
		}

		inner = cmp
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build ULNASTransport: %v", err)
	}

	secured, err := encodeGNBUplinkNAS(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
	}

	encoded, err := ngap.BuildUplinkNASTransport(ngap.UplinkNASTransportParams{
		AMFUENGAPID: ue.AMFUENGAPID,
		RANUENGAPID: ue.RANUENGAPID,
		NASPDU:      secured,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GnbID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendNGAPResponse{}, nil
}

func cause5GSMFor(req *SendNGAPRequest) uint8 {
	if req != nil && req.FiveGSMCauseOverride != nil {
		return *req.FiveGSMCauseOverride
	}

	return nasMessage.Cause5GSMProtocolErrorUnspecified
}

func sendInner5GSM(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest, inner []byte) (*SendNGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build ULNASTransport: %v", err)
	}

	secured, err := encodeGNBUplinkNAS(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
	}

	encoded, err := ngap.BuildUplinkNASTransport(ngap.UplinkNASTransportParams{
		AMFUENGAPID: ue.AMFUENGAPID,
		RANUENGAPID: ue.RANUENGAPID,
		NASPDU:      secured,
		MCC:         gnb.MCC,
		MNC:         gnb.MNC,
		TAC:         gnb.TAC,
		GnbID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendNGAPResponse{}, nil
}

func handleGnBPDUSessionModificationCommandReject(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		rej, err := nasCodec.BuildPDUSessionModificationCommandReject(pduSessionID, ptiFor(req), cause5GSMFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionModificationCommandReject: %v", err)
		}

		inner = rej
	}

	return sendInner5GSM(gnb, ue, t, req, inner)
}

func handleGnBStatus5GSM(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) (*SendNGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		st, err := nasCodec.BuildPDUSessionStatus5GSM(pduSessionID, ptiFor(req), cause5GSMFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build Status5GSM: %v", err)
		}

		inner = st
	}

	return sendInner5GSM(gnb, ue, t, req, inner)
}
