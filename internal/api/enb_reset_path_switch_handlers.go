// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/naseps"
	"github.com/ellanetworks/3gpp-server/internal/s1ap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
)

// Reset is non-UE-associated: it resets the whole S1 interface, or the UE
// associations named in reset_ue_ids (TS 36.413 §8.7.1).
func handleENBReset(ctx context.Context, enb *store.ENBContext, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBUES1APResponse, error) {
	var connections []s1ap.ResetConnection

	for _, ueID := range req.ResetUEIDs {
		ue, ok := enb.GetUE(ueID)
		if !ok {
			return nil, httpErrorf(http.StatusNotFound, "ue %s not found", ueID)
		}

		mme := ue.MMEUES1APID
		enbID := ue.ENBUES1APID
		connections = append(connections, s1ap.ResetConnection{MMEUES1APID: &mme, ENBUES1APID: &enbID})
	}

	pdu, err := s1ap.BuildReset(len(connections) == 0, connections)
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build Reset: %v", err)
	}

	if err := t.Send(pdu, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	resp, err := t.WaitForMessage(ctx, "ResetAcknowledge", "ErrorIndication")
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for ResetAcknowledge: %v", err)
	}

	return &SendENBUES1APResponse{S1AP: resp}, nil
}

func handleENBRawS1AP(ctx context.Context, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBUES1APResponse, error) {
	pdu, err := hex.DecodeString(*req.RawS1APPDU)
	if err != nil {
		return nil, httpErrorf(http.StatusBadRequest, "decode raw_s1ap_pdu: %v", err)
	}

	if err := t.Send(pdu, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	if len(req.WaitFor) == 0 {
		return &SendENBUES1APResponse{}, nil
	}

	resp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for %v: %v", req.WaitFor, err)
	}

	return &SendENBUES1APResponse{S1AP: resp}, nil
}

func handleENBPathSwitchRequest(ctx context.Context, enb *store.ENBContext, t *transport.S1APTransport, req *SendENBS1APRequest) (*SendENBUES1APResponse, error) {
	if req.MMEUES1APID == nil || req.ENBUES1APID == nil {
		return nil, httpErrorf(http.StatusBadRequest, "mme_ue_s1ap_id and enb_ue_s1ap_id are required")
	}

	if len(req.ERABs) == 0 {
		return nil, httpErrorf(http.StatusBadRequest, "erabs is required for path_switch_request")
	}

	erab := req.ERABs[0]

	teid := erab.DLTeid
	if teid == 0 {
		teid = *req.ENBUES1APID + 0x1000
	}

	// The S1AP encoding drops the EEA0/EIA0 bit, so shift the octets left.
	netcap := naseps.DefaultUENetworkCapability

	encAlg := uint16(netcap[0]<<1) << 8
	intAlg := uint16(netcap[1]<<1) << 8

	if req.PathSwitchEEA != nil {
		encAlg = *req.PathSwitchEEA
	}

	if req.PathSwitchEIA != nil {
		intAlg = *req.PathSwitchEIA
	}

	encoded, err := s1ap.BuildPathSwitchRequest(s1ap.PathSwitchRequestParams{
		ENBUES1APID:                   *req.ENBUES1APID,
		SourceMMEUES1APID:             *req.MMEUES1APID,
		ERABID:                        erab.ID,
		TargetS1UAddr:                 enb.N3Addr,
		TargetTEID:                    teid,
		MCC:                           enb.MCC,
		MNC:                           enb.MNC,
		TAC:                           enb.TAC,
		CellID:                        1,
		EncryptionAlgorithms:          encAlg,
		IntegrityProtectionAlgorithms: intAlg,
		Duplicate:                     req.DuplicateERAB,
	})
	if err != nil {
		return nil, httpErrorf(http.StatusInternalServerError, "build PathSwitchRequest: %v", err)
	}

	if err := t.Send(encoded, false); err != nil {
		return nil, httpErrorf(http.StatusBadGateway, "SCTP send: %v", err)
	}

	if len(req.WaitFor) == 0 {
		return &SendENBUES1APResponse{}, nil
	}

	resp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		return nil, httpErrorf(http.StatusGatewayTimeout, "waiting for %v: %v", req.WaitFor, err)
	}

	return &SendENBUES1APResponse{S1AP: resp}, nil
}
