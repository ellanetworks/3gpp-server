// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

func handlePathSwitchRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, t *transport.NGAPTransport, req *SendGnBNGAPRequest) {
	if req.AmfUeNgapID == nil || req.RanUeNgapID == nil {
		writeError(w, http.StatusBadRequest, "amf_ue_ngap_id and ran_ue_ngap_id are required")
		return
	}

	if len(req.PDUSessions) == 0 {
		writeError(w, http.StatusBadRequest, "pdu_sessions is required for path_switch_request")
		return
	}

	var sessions []ngap.PathSwitchSession

	for _, ps := range req.PDUSessions {
		dlIP := ps.DLIP
		if dlIP == "" {
			dlIP = "127.0.0.1"
		}

		teid := ps.DLTeid
		if teid == 0 {
			teid = 1
		}

		var rawTransfer []byte

		if ps.RawTransfer != nil {
			decoded, err := hex.DecodeString(*ps.RawTransfer)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_transfer: %v", err))
				return
			}

			rawTransfer = decoded
		}

		sessions = append(sessions, ngap.PathSwitchSession{PDUSessionID: ps.ID, DLTeid: teid, DLIP: dlIP, RawTransfer: rawTransfer})
	}

	secCaps, err := pathSwitchSecurityCapabilities(req.UESecurityCapabilities)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	encoded, err := ngap.BuildPathSwitchRequest(*req.RanUeNgapID, *req.AmfUeNgapID, gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, secCaps, sessions, req.FailedPDUSessions, req.OmitIEs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PathSwitchRequest: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	if len(req.WaitFor) == 0 {
		writeJSON(w, http.StatusOK, SendNGAPResponse{})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.WaitFor, err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func pathSwitchSecurityCapabilities(in *UESecurityCapabilitiesInput) (ngap.UESecurityCapabilities, error) {
	parse := func(name, s string, def []byte) ([]byte, error) {
		if s == "" {
			return def, nil
		}

		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("decode %s security capability %q: %w", name, s, err)
		}

		if len(b) != 2 {
			return nil, fmt.Errorf("%s security capability must be 2 bytes, got %d", name, len(b))
		}

		return b, nil
	}

	var (
		caps ngap.UESecurityCapabilities
		err  error
	)

	if in == nil {
		in = &UESecurityCapabilitiesInput{}
	}

	if caps.NREncryption, err = parse("nr_encryption", in.NREncryption, []byte{0xe0, 0x00}); err != nil {
		return caps, err
	}

	if caps.NRIntegrity, err = parse("nr_integrity", in.NRIntegrity, []byte{0xe0, 0x00}); err != nil {
		return caps, err
	}

	if caps.EUTRAEncryption, err = parse("eutra_encryption", in.EUTRAEncryption, []byte{0x00, 0x00}); err != nil {
		return caps, err
	}

	if caps.EUTRAIntegrity, err = parse("eutra_integrity", in.EUTRAIntegrity, []byte{0x00, 0x00}); err != nil {
		return caps, err
	}

	return caps, nil
}

func handleRawNGAP(w http.ResponseWriter, r *http.Request, t *transport.NGAPTransport, req *SendGnBNGAPRequest) {
	pdu, err := hex.DecodeString(*req.RawNGAPPDU)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_ngap_pdu: %v", err))
		return
	}

	if err := t.Send(pdu, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	if len(req.WaitFor) == 0 {
		writeJSON(w, http.StatusOK, SendNGAPResponse{})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.WaitFor, err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func handleNGReset(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, t *transport.NGAPTransport, req *SendGnBNGAPRequest) {
	var connections []ngap.NGResetConnection

	for _, ueID := range req.ResetUEIDs {
		ue, ok := gnb.GetUE(ueID)
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
			return
		}

		amf := ue.AmfUeNgapID
		ran := ue.RanUeNgapID
		connections = append(connections, ngap.NGResetConnection{AmfUeNgapID: &amf, RanUeNgapID: &ran})
	}

	encoded, err := ngap.BuildNGReset(connections)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build NGReset: %v", err))
		return
	}

	if err := t.Send(encoded, true); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, "NGResetAcknowledge", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for NGResetAcknowledge: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}
