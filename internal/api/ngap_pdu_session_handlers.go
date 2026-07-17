// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"fmt"
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
		PDUSessionID: pduSessionID,
		N3GnbIP:      gnb.N3Addr,
		DLTeid:       dlTeid,
		QFI:          1,
	}

	gnbN3IsV6 := false
	if a, err := netip.ParseAddr(gnb.N3Addr); err == nil {
		gnbN3IsV6 = a.Is6()
	}

	for _, ie := range ngapResp.IEs {
		for _, item := range ie.PDUSessionSetupItems {
			if item.PDUSessionID == pduSessionID {
				info.ULTeid = item.ULTeid
				if gnbN3IsV6 {
					info.UPFIP = firstNonEmpty(item.UPFN3IPv6, item.UPFN3IP)
				} else {
					info.UPFIP = firstNonEmpty(item.UPFN3IP, item.UPFN3IPv6)
				}
			}
		}
	}

	if nasResp != nil {
		info.UEIP = nasResp.PDUAddress
	}

	gnb.StorePDUSession(ue.RanUeNgapID, info)
}

func handlePDUSessionEstablishmentRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, gt *gtpu.Endpoint, req *SendNGAPRequest) {
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
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		sendUplinkAndWait(w, r, gnb, ue, t, req, raw, "PDUSessionResourceSetupRequest", "DownlinkNASTransport", "ErrorIndication")

		return
	}

	var (
		pduReq []byte
		err    error
	)

	if req.InnerSMPayload != nil {
		pduReq, err = hex.DecodeString(*req.InnerSMPayload)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode inner_sm_payload: %v", err))
			return
		}
	} else {
		pduReq, err = nasCodec.BuildPDUSessionEstablishmentRequest(&nasCodec.PDUSessionEstablishmentRequestOpts{
			PDUSessionID:   pduSessionID,
			PDUSessionType: pduSessionType,
			PTI:            ptiFor(req),
			AlwaysOn:       req.AlwaysOnRequested != nil && *req.AlwaysOnRequested,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionEstablishmentRequest: %v", err))
			return
		}
	}

	ulNas, err := nasCodec.BuildULNASTransport(pduSessionID, pduReq, ue.DNN, ue.SST, ue.SD)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	securedPDU, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas,
		gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, securedPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"PDUSessionResourceSetupRequest", "DownlinkNASTransport", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for PDU establishment response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		if ie.NasPDU != nil {
			nasPDUBytes, err := hex.DecodeString(*ie.NasPDU)
			if err != nil {
				continue
			}

			nasResp, _ = nasCodec.DecodeSecuredNAS(ue, nasPDUBytes)
		}
	}

	if ngapResp.MessageType == "PDUSessionResourceSetupRequest" {
		dlTeid := uint32(ue.RanUeNgapID)<<8 | uint32(pduSessionID)

		pduSetupResp, err := ngap.BuildPDUSessionResourceSetupResponse(
			ue.AmfUeNgapID, ue.RanUeNgapID, int64(pduSessionID), dlTeid, gnb.N3Addr)
		if err == nil {
			_ = t.Send(pduSetupResp, false)
		}

		if gt != nil {
			captureTunnel(gnb, ue, int64(pduSessionID), dlTeid, ngapResp, nasResp)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
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

func handlePDUSessionReleaseRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		relReq, err := nasCodec.BuildPDUSessionReleaseRequest(pduSessionID, ptiFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionReleaseRequest: %v", err))
			return
		}

		inner = relReq
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, secured, "PDUSessionResourceReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
}

func handlePDUSessionModificationRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		modReq, err := nasCodec.BuildPDUSessionModificationRequest(pduSessionID, ptiFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionModificationRequest: %v", err))
			return
		}

		inner = modReq
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, secured, "PDUSessionResourceModifyRequest", "DownlinkNASTransport", "ErrorIndication")
}

func handlePDUSessionReleaseComplete(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		cmp, err := nasCodec.BuildPDUSessionReleaseComplete(pduSessionID, ptiFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionReleaseComplete: %v", err))
			return
		}

		inner = cmp
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, secured,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func handlePDUSessionModificationComplete(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		cmp, err := nasCodec.BuildPDUSessionModificationComplete(pduSessionID, ptiFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionModificationComplete: %v", err))
			return
		}

		inner = cmp
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, secured,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func cause5GSMFor(req *SendNGAPRequest) uint8 {
	if req != nil && req.Cause5GSMOverride != nil {
		return *req.Cause5GSMOverride
	}

	return nasMessage.Cause5GSMProtocolErrorUnspecified
}

func sendInner5GSM(w http.ResponseWriter, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest, inner []byte) {
	pduSessionID := pduSessionIDForRelease(ue)

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, req.RequestTypeOverride, inner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ULNASTransport: %v", err))
		return
	}

	secured, err := nasCodec.EncodeNasPduWithSecurity(ue, ulNas, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, secured,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

func handlePDUSessionModificationCommandReject(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		rej, err := nasCodec.BuildPDUSessionModificationCommandReject(pduSessionID, ptiFor(req), cause5GSMFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionModificationCommandReject: %v", err))
			return
		}

		inner = rej
	}

	sendInner5GSM(w, gnb, ue, t, req, inner)
}

func handleStatus5GSM(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	pduSessionID := pduSessionIDForRelease(ue)

	var inner []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		inner = raw
	} else {
		st, err := nasCodec.BuildPDUSessionStatus5GSM(pduSessionID, ptiFor(req), cause5GSMFor(req))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build Status5GSM: %v", err))
			return
		}

		inner = st
	}

	sendInner5GSM(w, gnb, ue, t, req, inner)
}
