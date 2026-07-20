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

func handleGNBPathSwitchRequest(ctx context.Context, gnb *store.GNBContext, t *transport.NGAPTransport, req *SendGNBNGAPRequest) (*SendGNBUENGAPResponse, error) {
	if req.AMFUENGAPID == nil || req.RANUENGAPID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "amf_ue_ngap_id and ran_ue_ngap_id are required")
	}

	if len(req.PDUSessions) == 0 {
		return nil, httpErrorf(http.StatusBadRequest, "pdu_sessions is required for path_switch_request")
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
				return nil, httpErrorf(http.StatusBadRequest, "decode raw_transfer: %v", err)
			}

			rawTransfer = decoded
		}

		sessions = append(sessions, ngap.PathSwitchSession{PDUSessionID: ps.ID, DLTeid: teid, DLIP: dlIP, RawTransfer: rawTransfer})
	}

	secCaps, err := pathSwitchSecurityCapabilities(req.UESecurityCapabilities)
	if err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "%v", err)
	}

	encoded, err := ngap.BuildPathSwitchRequest(ngap.PathSwitchRequestParams{
		RANUENGAPID:       *req.RANUENGAPID,
		SourceAMFUENGAPID: *req.AMFUENGAPID,
		MCC:               gnb.MCC,
		MNC:               gnb.MNC,
		TAC:               gnb.TAC,
		GNBID:             gnb.GNBID,
		SecCaps:           secCaps,
		Sessions:          sessions,
		Failed:            req.FailedPDUSessions,
		OmitIEs:           req.OmitIEs,
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build PathSwitchRequest: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	if len(req.WaitFor) == 0 {
		return &SendGNBUENGAPResponse{}, nil
	}

	ngapResp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for %v: %v", req.WaitFor, err)
	}

	return &SendGNBUENGAPResponse{NGAP: ngapResp}, nil
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

func handleGNBRawNGAP(ctx context.Context, t *transport.NGAPTransport, req *SendGNBNGAPRequest) (*SendGNBUENGAPResponse, error) {
	pdu, err := hex.DecodeString(*req.RawNGAPPDU)
	if err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "decode raw_ngap_pdu: %v", err)
	}

	if err := t.Send(pdu, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	if len(req.WaitFor) == 0 {
		return &SendGNBUENGAPResponse{}, nil
	}

	ngapResp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for %v: %v", req.WaitFor, err)
	}

	return &SendGNBUENGAPResponse{NGAP: ngapResp}, nil
}

func handleGNBNGReset(ctx context.Context, gnb *store.GNBContext, t *transport.NGAPTransport, req *SendGNBNGAPRequest) (*SendGNBUENGAPResponse, error) {
	var connections []ngap.NGResetConnection

	for _, ueID := range req.ResetUEIDs {
		ue, ok := gnb.GetUE(ueID)
		if !ok {
			return nil, httpErrorf(http.StatusNotFound, "ue %s not found", ueID)
		}

		amf := ue.AMFUENGAPID
		ran := ue.RANUENGAPID
		connections = append(connections, ngap.NGResetConnection{AMFUENGAPID: &amf, RANUENGAPID: &ran})
	}

	encoded, err := ngap.BuildNGReset(len(connections) == 0, connections)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build NGReset: %v", err)
	}

	if err := t.Send(encoded, true); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	ngapResp, err := t.WaitForMessage(ctx, "NGResetAcknowledge", "ErrorIndication")
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for NGResetAcknowledge: %v", err)
	}

	return &SendGNBUENGAPResponse{NGAP: ngapResp}, nil
}
