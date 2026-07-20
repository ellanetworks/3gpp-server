// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/netip"

	"github.com/ellanetworks/3gpp-server/internal/gtpu"
	"github.com/ellanetworks/3gpp-server/internal/nas5gs"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
)

func captureTunnel(gnb *store.GNBContext, ue *store.UEContext, pduSessionID int64, dlTeid uint32, ngapResp *ngap.NGAPResponse, nasResp *nas5gs.NASResponse) {
	info := &store.PDUSessionInfo{
		PDUSessionID: uint8(pduSessionID),
		N3GNBIP:      gnb.N3Addr,
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
				info.UPFIP = firstNonEmpty(item.TransportLayerAddressIPv6, item.TransportLayerAddress)
			} else {
				info.UPFIP = firstNonEmpty(item.TransportLayerAddress, item.TransportLayerAddressIPv6)
			}
		}
	}

	if nasResp != nil {
		info.UEIP = nasResp.PDUAddress
	}

	ue.PDUSessions[uint8(pduSessionID)] = info
}

func handleGNBPDUSessionEstablishmentRequest(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, gt *gtpu.Endpoint, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
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
		pduReq, err = nas5gs.BuildPDUSessionEstablishmentRequest(nas5gs.PDUSessionEstablishmentRequestParams{
			PDUSessionID:   pduSessionID,
			PDUSessionType: pduSessionType,
			PTI:            ptiFor(req),
			AlwaysOn:       req.AlwaysOnRequested != nil && *req.AlwaysOnRequested,
		})
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionEstablishmentRequest: %v", err)
		}
	}

	ulNas, err := nas5gs.BuildULNASTransport(nas5gs.ULNASTransportParams{
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
		GNBID:       gnb.GNBID,
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

	var nasResp *nas5gs.NASResponse

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

	return &SendGNBUENGAPResponse{
		NGAP:        ngapResp,
		NAS:         nasResp,
		MACVerified: macVerified,
	}, nil
}

func ptiFor(req *SendGNBUENGAPRequest) uint8 {
	if req != nil && req.PTI != nil {
		return *req.PTI
	}

	return 0x01
}

func pduSessionIDForRelease(ue *store.UEContext) uint8 {
	if ue.PDUSessionID >= 1 && ue.PDUSessionID <= 15 {
		return ue.PDUSessionID
	}

	return 1
}

func handleGNBPDUSessionReleaseRequest(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		relReq, err := nas5gs.BuildPDUSessionReleaseRequest(pduSessionID, ptiFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionReleaseRequest: %v", err)
		}

		inner = relReq
	}

	ulNas, err := nas5gs.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build ULNASTransport: %v", err)
	}

	secured, err := encodeGNBUplinkNAS(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, secured, "PDUSessionResourceReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
}

func handleGNBPDUSessionModificationRequest(ctx context.Context, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		modReq, err := nas5gs.BuildPDUSessionModificationRequest(pduSessionID, ptiFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionModificationRequest: %v", err)
		}

		inner = modReq
	}

	ulNas, err := nas5gs.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build ULNASTransport: %v", err)
	}

	secured, err := encodeGNBUplinkNAS(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nil)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NAS security encode: %v", err)
	}

	return sendUplinkAndWait(ctx, gnb, ue, t, req, secured, "PDUSessionResourceModifyRequest", "DownlinkNASTransport", "ErrorIndication")
}

func handleGNBPDUSessionReleaseComplete(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		cmp, err := nas5gs.BuildPDUSessionReleaseComplete(pduSessionID, ptiFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionReleaseComplete: %v", err)
		}

		inner = cmp
	}

	ulNas, err := nas5gs.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
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
		GNBID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendGNBUENGAPResponse{}, nil
}

func handleGNBPDUSessionModificationComplete(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		cmp, err := nas5gs.BuildPDUSessionModificationComplete(pduSessionID, ptiFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionModificationComplete: %v", err)
		}

		inner = cmp
	}

	ulNas, err := nas5gs.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
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
		GNBID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendGNBUENGAPResponse{}, nil
}

func cause5GSMFor(req *SendGNBUENGAPRequest) uint8 {
	if req != nil && req.FiveGSMCauseOverride != nil {
		return *req.FiveGSMCauseOverride
	}

	return nasMessage.Cause5GSMProtocolErrorUnspecified
}

func sendInner5GSM(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest, inner []byte) (*SendGNBUENGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	ulNas, err := nas5gs.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
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
		GNBID:       gnb.GNBID,
		Overrides:   uplinkOverrides(req),
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "NGAP encode: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	return &SendGNBUENGAPResponse{}, nil
}

func handleGNBPDUSessionModificationCommandReject(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		rej, err := nas5gs.BuildPDUSessionModificationCommandReject(pduSessionID, ptiFor(req), cause5GSMFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build PDUSessionModificationCommandReject: %v", err)
		}

		inner = rej
	}

	return sendInner5GSM(gnb, ue, t, req, inner)
}

func handleGNBStatus5GSM(gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendGNBUENGAPRequest) (*SendGNBUENGAPResponse, error) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			return nil, httpErrorf(http.StatusBadRequest, "decode raw_nas_pdu: %v", err)
		}

		inner = raw
	} else {
		st, err := nas5gs.BuildPDUSessionStatus5GSM(pduSessionID, ptiFor(req), cause5GSMFor(req))
		if err != nil {
			return nil, httpErrorf(http.StatusInternalServerError, "build Status5GSM: %v", err)
		}

		inner = st
	}

	return sendInner5GSM(gnb, ue, t, req, inner)
}
