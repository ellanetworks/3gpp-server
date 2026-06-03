package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ellanetworks/3gpp-server/internal/crypto"
	nasCodec "github.com/ellanetworks/3gpp-server/internal/nas"
	"github.com/ellanetworks/3gpp-server/internal/ngap"
	"github.com/ellanetworks/3gpp-server/internal/store"
	"github.com/ellanetworks/3gpp-server/internal/transport"
	gonas "github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

func (h *Handler) SendNGAP(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGnB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	ue, ok := gnb.GetUE(ueID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return
	}

	t, ok := h.Transports[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no active SCTP transport")
		return
	}

	var req SendNGAPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	switch req.MessageType {
	case "registration_request":
		handleRegistrationRequest(w, r, gnb, ue, t, &req)
	case "authentication_response":
		handleAuthenticationResponse(w, r, gnb, ue, t, &req)
	case "security_mode_complete":
		handleSecurityModeComplete(w, r, gnb, ue, t, &req)
	case "registration_complete":
		handleRegistrationComplete(w, r, gnb, ue, t, &req)
	case "pdu_session_establishment_request":
		handlePDUSessionEstablishmentRequest(w, r, gnb, ue, t, &req)
	case "deregistration_request":
		handleDeregistrationRequest(w, r, gnb, ue, t, &req)
	case "ue_context_release_request":
		handleUEContextReleaseRequest(w, r, gnb, ue, t, &req)
	case "service_request":
		handleServiceRequest(w, r, gnb, ue, t, &req)
	case "identity_response":
		handleIdentityResponse(w, r, gnb, ue, t, &req)
	case "pdu_session_release_request":
		handlePDUSessionReleaseRequest(w, r, gnb, ue, t, &req)
	case "pdu_session_modification_request":
		handlePDUSessionModificationRequest(w, r, gnb, ue, t, &req)
	case "pdu_session_release_complete":
		handlePDUSessionReleaseComplete(w, r, gnb, ue, t, &req)
	case "authentication_failure":
		handleAuthenticationFailure(w, r, gnb, ue, t, &req)
	case "security_mode_reject":
		handleSecurityModeReject(w, r, gnb, ue, t, &req)
	case "handover_required":
		handleHandoverRequired(w, r, gnb, ue, t, &req)
	case "handover_cancel":
		handleHandoverCancel(w, r, gnb, ue, t, &req)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported message_type: %s", req.MessageType))
	}
}

// SendGnBNGAP sends a gNB-level (non-UE-associated) NGAP message on the gNB's
// existing N2 association.
func (h *Handler) SendGnBNGAP(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	gnb, err := h.Store.GetGnB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	t, ok := h.Transports[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no active SCTP transport")
		return
	}

	var req SendGnBNGAPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// raw_ngap_pdu bypasses message_type entirely.
	if req.RawNGAPPDU != nil {
		handleRawNGAP(w, r, t, &req)
		return
	}

	switch req.MessageType {
	case "ng_reset":
		handleNGReset(w, r, gnb, t, &req)
	case "handover_request_acknowledge":
		handleHandoverRequestAcknowledge(w, t, &req)
	case "handover_failure":
		handleHandoverFailure(w, t, &req)
	case "handover_notify":
		handleHandoverNotify(w, gnb, t, &req)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported message_type: %s", req.MessageType))
	}
}

// effectiveRanID and effectiveAmfID return the UE NGAP IDs actually placed on
// the wire for a send — the request override when present, else the stored
// value. The downlink response echoes these, so they are the keys to correlate
// it back to this UE.
func effectiveRanID(req *SendNGAPRequest, ue *store.UEContext) int64 {
	if req != nil && req.RanUeNgapIDOverride != nil {
		return *req.RanUeNgapIDOverride
	}

	return ue.RanUeNgapID
}

func effectiveAmfID(req *SendNGAPRequest, ue *store.UEContext) int64 {
	if req != nil && req.AmfUeNgapIDOverride != nil {
		return *req.AmfUeNgapIDOverride
	}

	return ue.AmfUeNgapID
}

// ueNGAPMatcher matches a downlink NGAP PDU to a specific UE by its NGAP IDs, so
// concurrent waiters on one gNB association don't consume each other's downlink.
// The RAN UE NGAP ID is always known for a send (it is mandatory in every
// UE-associated message), so it is matched exactly — including the legitimate
// value 0. The AMF UE NGAP ID is a secondary key: it is the AMF's to assign, so
// amfID of 0 means "not yet known" and is skipped. A PDU carrying no UE NGAP ID
// (e.g. an association-level Error Indication) matches any waiter.
func ueNGAPMatcher(ranID, amfID int64) func(*ngap.NGAPResponse) bool {
	return func(resp *ngap.NGAPResponse) bool {
		var msgRan, msgAmf *int64

		for i := range resp.IEs {
			if resp.IEs[i].RanUeNgapID != nil {
				msgRan = resp.IEs[i].RanUeNgapID
			}

			if resp.IEs[i].AmfUeNgapID != nil {
				msgAmf = resp.IEs[i].AmfUeNgapID
			}
		}

		if msgRan == nil && msgAmf == nil {
			return true
		}

		if msgRan != nil && *msgRan == ranID {
			return true
		}

		if msgAmf != nil && amfID != 0 && *msgAmf == amfID {
			return true
		}

		return false
	}
}

// AwaitUEMessage waits for an unsolicited downlink NGAP message addressed to a
// specific UE on the gNB's association, letting many UEs share one gNB without
// claiming each other's downlink.
func (h *Handler) AwaitUEMessage(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")
	ueID := r.PathValue("ue_id")

	gnb, err := h.Store.GetGnB(gnbID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	ue, ok := gnb.GetUE(ueID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("ue %s not found", ueID))
		return
	}

	t, ok := h.Transports[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no active SCTP transport")
		return
	}

	var req AwaitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if len(req.MessageTypes) == 0 {
		writeError(w, http.StatusBadRequest, "message_types is required")
		return
	}

	timeout := 5 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(ue.RanUeNgapID, ue.AmfUeNgapID), req.MessageTypes...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.MessageTypes, err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

// AwaitGnBMessage waits for an unsolicited downlink NGAP message to arrive on
// the gNB's N2 association (e.g. Handover Request on a target gNB, or Handover
// Command / UE Context Release Command on a source gNB).
func (h *Handler) AwaitGnBMessage(w http.ResponseWriter, r *http.Request) {
	gnbID := r.PathValue("gnb_id")

	if _, err := h.Store.GetGnB(gnbID); err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("gnb not found: %v", err))
		return
	}

	t, ok := h.Transports[gnbID]
	if !ok {
		writeError(w, http.StatusBadRequest, "gnb has no active SCTP transport")
		return
	}

	var req AwaitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if len(req.MessageTypes) == 0 {
		writeError(w, http.StatusBadRequest, "message_types is required")
		return
	}

	timeout := 5 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, req.MessageTypes...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.MessageTypes, err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

// handleHandoverRequired sends a HANDOVER REQUIRED for the UE toward the target
// gNB (TS 38.413 §8.4.1). Send-only: the resulting Handover Command arrives
// asynchronously (await it on the source gNB).
func handleHandoverRequired(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	if req.TargetGnbID == nil {
		writeError(w, http.StatusBadRequest, "target_gnb_id is required for handover_required")
		return
	}

	pduSessionID := pduSessionIDForRelease(ue)

	amfUeNgapID := ue.AmfUeNgapID
	if req.AmfUeNgapIDOverride != nil {
		amfUeNgapID = *req.AmfUeNgapIDOverride
	}

	ranUeNgapID := ue.RanUeNgapID
	if req.RanUeNgapIDOverride != nil {
		ranUeNgapID = *req.RanUeNgapIDOverride
	}

	pduSessionIDs := []int64{int64(pduSessionID)}
	if len(req.PDUSessionIDs) > 0 {
		pduSessionIDs = req.PDUSessionIDs
	}

	encoded, err := ngap.BuildHandoverRequired(amfUeNgapID, ranUeNgapID, *req.TargetGnbID,
		gnb.MCC, gnb.MNC, gnb.TAC, pduSessionIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverRequired: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

// handleHandoverCancel sends a HANDOVER CANCEL for the UE (TS 38.413 §8.4.5) and
// returns the AMF's Handover Cancel Acknowledge (or Error Indication).
func handleHandoverCancel(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	amfUeNgapID := ue.AmfUeNgapID
	if req.AmfUeNgapIDOverride != nil {
		amfUeNgapID = *req.AmfUeNgapIDOverride
	}

	ranUeNgapID := ue.RanUeNgapID
	if req.RanUeNgapIDOverride != nil {
		ranUeNgapID = *req.RanUeNgapIDOverride
	}

	cause := ngap.CauseRadioNetworkHandoverCancelled
	if req.HandoverCancelCause != nil {
		cause = *req.HandoverCancelCause
	}

	encoded, err := ngap.BuildHandoverCancel(amfUeNgapID, ranUeNgapID, cause)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverCancel: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, "HandoverCancelAcknowledge", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for HandoverCancelAcknowledge: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

// handleHandoverRequestAcknowledge sends a HANDOVER REQUEST ACKNOWLEDGE from the
// target gNB (TS 38.413 §8.4.2). Send-only.
func handleHandoverRequestAcknowledge(w http.ResponseWriter, t *transport.SCTPTransport, req *SendGnBNGAPRequest) {
	if req.AmfUeNgapID == nil || req.RanUeNgapID == nil {
		writeError(w, http.StatusBadRequest, "amf_ue_ngap_id and ran_ue_ngap_id are required")
		return
	}

	if len(req.PDUSessions) == 0 {
		writeError(w, http.StatusBadRequest, "pdu_sessions is required for handover_request_acknowledge")
		return
	}

	var sessions []ngap.HandoverAdmittedSession

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

		sessions = append(sessions, ngap.HandoverAdmittedSession{PDUSessionID: ps.ID, DLTeid: teid, DLIP: dlIP, RawTransfer: rawTransfer})
	}

	encoded, err := ngap.BuildHandoverRequestAcknowledge(*req.AmfUeNgapID, *req.RanUeNgapID, sessions, req.FailedPDUSessions)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverRequestAcknowledge: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

// handleHandoverNotify sends a HANDOVER NOTIFY from the target gNB once the UE
// has arrived (TS 38.413 §8.4.3). Send-only.
func handleHandoverNotify(w http.ResponseWriter, gnb *store.GnBContext, t *transport.SCTPTransport, req *SendGnBNGAPRequest) {
	if req.AmfUeNgapID == nil || req.RanUeNgapID == nil {
		writeError(w, http.StatusBadRequest, "amf_ue_ngap_id and ran_ue_ngap_id are required")
		return
	}

	encoded, err := ngap.BuildHandoverNotify(*req.AmfUeNgapID, *req.RanUeNgapID, gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverNotify: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

// handleHandoverFailure sends a HANDOVER FAILURE from the target gNB rejecting a
// handover (TS 38.413 §8.4.2.3). Send-only: the AMF's Handover Preparation
// Failure (or Error Indication) arrives asynchronously.
func handleHandoverFailure(w http.ResponseWriter, t *transport.SCTPTransport, req *SendGnBNGAPRequest) {
	if req.AmfUeNgapID == nil {
		writeError(w, http.StatusBadRequest, "amf_ue_ngap_id is required for handover_failure")
		return
	}

	cause := ngap.CauseRadioNetworkHoFailureInTarget
	if req.Cause != nil {
		cause = *req.Cause
	}

	encoded, err := ngap.BuildHandoverFailure(*req.AmfUeNgapID, cause)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build HandoverFailure: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{})
}

// handleRawNGAP writes the caller-supplied PDU onto the N2 association verbatim.
// With wait_for it returns the first matching downlink message; otherwise it is
// fire-and-forget.
func handleRawNGAP(w http.ResponseWriter, r *http.Request, t *transport.SCTPTransport, req *SendGnBNGAPRequest) {
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

	timeout := 5 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, req.WaitFor...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for %v: %v", req.WaitFor, err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

// handleNGReset sends an NG RESET (TS 38.413 §8.7.4) initiated by the gNB: a
// full reset of the NG interface when no UEs are listed, or a partial reset of
// the listed UEs' associations. The AMF answers with NG RESET ACKNOWLEDGE.
func handleNGReset(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, t *transport.SCTPTransport, req *SendGnBNGAPRequest) {
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

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, "NGResetAcknowledge", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for NGResetAcknowledge: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func uplinkOverrides(req *SendNGAPRequest) *ngap.UplinkNASTransportOverrides {
	if req.AmfUeNgapIDOverride == nil && req.RanUeNgapIDOverride == nil {
		return nil
	}

	return &ngap.UplinkNASTransportOverrides{
		AmfUeNgapID: req.AmfUeNgapIDOverride,
		RanUeNgapID: req.RanUeNgapIDOverride,
	}
}

func initialUEOverrides(req *SendNGAPRequest) *ngap.InitialUEMessageOverrides {
	if req.RRCEstablishmentCauseOverride == nil && req.UEContextRequestOverride == nil && req.RanUeNgapIDOverride == nil {
		return nil
	}

	return &ngap.InitialUEMessageOverrides{
		RRCEstablishmentCause: req.RRCEstablishmentCauseOverride,
		UEContextRequest:      req.UEContextRequestOverride,
		RanUeNgapID:           req.RanUeNgapIDOverride,
	}
}

func handleRegistrationRequest(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	if req.RawNASPDU != nil {
		nasPDU, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		if req.ExistingConnection {
			sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
			return
		}

		ngapMsg := ngap.BuildInitialUEMessageFromState(
			ue.RanUeNgapID, nasPDU,
			gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID, nil, initialUEOverrides(req),
		)
		sendAndWait(w, r, gnb, ue, t, req, ngapMsg, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")

		return
	}

	regType := uint8(nasCodec.RegistrationTypeInitial)
	if req.RegistrationType != nil {
		regType = *req.RegistrationType
	}

	// A mobility or periodic registration update from a UE that holds a 5G NAS
	// security context is integrity-protected with that context and carries its
	// ngKSI, so the AMF can reuse it and accept directly (TS 24.501 §5.5.1.3).
	// Initial registration is sent as a cleartext (plain) message.
	mobilityOrPeriodic := regType == nasCodec.RegistrationTypeMobility || regType == nasCodec.RegistrationTypePeriodic
	secured := mobilityOrPeriodic && len(ue.Kamf) > 0

	ngKsi := uint8(7) // "no key available"
	if secured {
		ngKsi = ue.NgKsi
	}

	nasPDU, err := nasCodec.BuildRegistrationRequest(&nasCodec.RegistrationRequestOpts{
		RegistrationType: regType,
		Suci:             ue.Suci,
		Guti:             ue.Guti,
		SecurityCap:      ue.UeSecurityCapability,
		NgKsi:            ngKsi,
		Overrides:        req,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build NAS RegistrationRequest: %v", err))
		return
	}

	if secured {
		nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, nasPDU, gonas.SecurityHeaderTypeIntegrityProtected)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	// After an N2 handover the UE is CM-CONNECTED on the target, so a Mobility
	// Registration Update travels on the existing UE-associated connection
	// (Uplink NAS Transport), not a new Initial UE Message.
	if req.ExistingConnection {
		sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
		return
	}

	ngapMsg := ngap.BuildInitialUEMessageFromState(
		ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID, nil, initialUEOverrides(req),
	)
	sendAndWait(w, r, gnb, ue, t, req, ngapMsg, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")
}

func handleAuthenticationResponse(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		var resStar []byte

		if req.ResStarOverride != nil {
			var err error

			resStar, err = hex.DecodeString(*req.ResStarOverride)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("decode res_star_override: %v", err))
				return
			}
		} else if len(ue.LastRAND) == 0 || len(ue.LastAUTN) == 0 {
			// No authentication challenge stored (e.g. the response is sent out
			// of order, before any registration). Send a zeroed RES* so the
			// message still reaches the AMF, which decides how to react. Use
			// res_star_override to supply a specific value.
			resStar = make([]byte, 16)
		} else {
			akaResult, err := crypto.ComputeResStar(ue.K, ue.OPc, ue.Sqn, ue.Supi, ue.Snn, ue.LastRAND, ue.LastAUTN)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("5G-AKA: %v", err))
				return
			}

			ue.Kamf = akaResult.Kamf
			resStar = akaResult.RESstar
		}

		var err error

		nasPDU, err = nasCodec.BuildAuthenticationResponse(resStar)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build AuthenticationResponse: %v", err))
			return
		}
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
}

func handleSecurityModeComplete(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		// The NAS message container replays the registration request the UE
		// sent; keep its registration type consistent with that request.
		innerRegType := uint8(nasCodec.RegistrationTypeInitial)
		if req.RegistrationType != nil {
			innerRegType = *req.RegistrationType
		}

		regReqPDU, err := nasCodec.BuildRegistrationRequest(&nasCodec.RegistrationRequestOpts{
			RegistrationType: innerRegType,
			Suci:             ue.Suci,
			Guti:             ue.Guti,
			SecurityCap:      ue.UeSecurityCapability,
			NgKsi:            ue.NgKsi,
			Overrides:        req,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build inner RegistrationRequest: %v", err))
			return
		}

		smcPDU, err := nasCodec.BuildSecurityModeComplete(regReqPDU, ue.IMEISV)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build SecurityModeComplete: %v", err))
			return
		}

		nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, smcPDU,
			gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "InitialContextSetupRequest", "DownlinkNASTransport", "ErrorIndication")
}

func handleRegistrationComplete(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	icsResp, err := ngap.BuildInitialContextSetupResponse(ue.AmfUeNgapID, ue.RanUeNgapID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build InitialContextSetupResponse: %v", err))
		return
	}

	if err := t.Send(icsResp, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send InitialContextSetupResponse: %v", err))
		return
	}

	var nasPDU []byte

	if req.RawNASPDU != nil {
		nasPDU, err = hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}
	} else {
		regCompletePDU, err := nasCodec.BuildRegistrationComplete()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build RegistrationComplete: %v", err))
			return
		}

		nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, regCompletePDU,
			gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication", "UEContextReleaseCommand")
}

func handlePDUSessionEstablishmentRequest(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
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
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
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

	// The N3 endpoint is synthesised — 3gpp-server does not run a user plane.
	// The DL TEID is made unique per session so multiple sessions don't collide.
	dlTeid := uint32(ue.RanUeNgapID)<<8 | uint32(pduSessionID)
	pduSetupResp, err := ngap.BuildPDUSessionResourceSetupResponse(
		ue.AmfUeNgapID, ue.RanUeNgapID, int64(pduSessionID), dlTeid, "10.3.0.3")
	if err == nil {
		_ = t.Send(pduSetupResp, false)
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
}

func handleDeregistrationRequest(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		switchOff := uint8(1)
		if req.DeregSwitchOff != nil {
			switchOff = *req.DeregSwitchOff
		}

		deregPDU, err := nasCodec.BuildDeregistrationRequest(&nasCodec.DeregistrationRequestOpts{
			Guti:      ue.Guti,
			Suci:      &ue.Suci,
			NgKsi:     ue.NgKsi,
			SwitchOff: switchOff,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build DeregistrationRequest: %v", err))
			return
		}

		nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, deregPDU,
			gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"UEContextReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for response: %v", err))
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

	if ngapResp.MessageType == "UEContextReleaseCommand" {
		releaseComplete, err := ngap.BuildUEContextReleaseComplete(ue.AmfUeNgapID, ue.RanUeNgapID)
		if err == nil {
			_ = t.Send(releaseComplete, false)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
}

// handleUEContextReleaseRequest sends a gNB-initiated UE CONTEXT RELEASE
// REQUEST and expects the AMF to answer with a UE CONTEXT RELEASE COMMAND, to
// which the gNB replies with UE CONTEXT RELEASE COMPLETE. This transitions the
// UE to CM-IDLE while it stays RM-REGISTERED.
func handleUEContextReleaseRequest(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	// Default cause: user-inactivity (TS 38.413 §9.3.1.2, radio-network value 20).
	cause := int64(20)
	if req.ReleaseCause != nil {
		cause = *req.ReleaseCause
	}

	amfUeNgapID := ue.AmfUeNgapID
	if req.AmfUeNgapIDOverride != nil {
		amfUeNgapID = *req.AmfUeNgapIDOverride
	}

	ranUeNgapID := ue.RanUeNgapID
	if req.RanUeNgapIDOverride != nil {
		ranUeNgapID = *req.RanUeNgapIDOverride
	}

	encoded, err := ngap.BuildUEContextReleaseRequest(amfUeNgapID, ranUeNgapID, cause)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build UEContextReleaseRequest: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"UEContextReleaseCommand", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for response: %v", err))
		return
	}

	if ngapResp.MessageType == "UEContextReleaseCommand" {
		releaseComplete, err := ngap.BuildUEContextReleaseComplete(ue.AmfUeNgapID, ue.RanUeNgapID)
		if err == nil {
			_ = t.Send(releaseComplete, false)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

// handleIdentityResponse answers an AMF IDENTITY REQUEST (TS 24.501 §5.4.3).
// It replies with the UE's SUCI by default; mobile_identity_override supplies a
// different identity (e.g. an IMEISV when the AMF requested the PEI). The
// response is sent plain before a security context exists, secured otherwise.
func handleIdentityResponse(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		mobileIdentity := ue.Suci.Buffer
		if req.MobileIdentityOverride != nil {
			b, err := hex.DecodeString(*req.MobileIdentityOverride)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("decode mobile_identity_override: %v", err))
				return
			}

			mobileIdentity = b
		}

		idPDU, err := nasCodec.BuildIdentityResponse(mobileIdentity)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build IdentityResponse: %v", err))
			return
		}

		nasPDU = idPDU

		if len(ue.Kamf) > 0 {
			nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, idPDU, gonas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
				return
			}
		}
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")
}

// pduSessionIDForRelease resolves the PDU session ID to release, defaulting to
// the UE's configured session.
func pduSessionIDForRelease(ue *store.UEContext) uint8 {
	if ue.PDUSessionID >= 1 && ue.PDUSessionID <= 15 {
		return ue.PDUSessionID
	}

	return 1
}

// handlePDUSessionReleaseRequest sends a UE-requested PDU SESSION RELEASE
// REQUEST (TS 24.501 §6.3.3). The SMF answers with a PDU Session Resource
// Release Command carrying the NAS Release Command; the gNB auto-replies with a
// Release Response (in sendRawAndWait).
func handlePDUSessionReleaseRequest(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
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
		relReq, err := nasCodec.BuildPDUSessionReleaseRequest(pduSessionID, 0x01)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionReleaseRequest: %v", err))
			return
		}

		inner = relReq
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, inner)
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

// handlePDUSessionModificationRequest sends a UE-requested PDU SESSION
// MODIFICATION REQUEST (TS 24.501 §6.4.2) on an existing PDU session. Per
// §6.4.2.3/§6.4.2.4 the network answers with a Modification Command or a
// Modification Reject (or a 5GSM STATUS for a PTI error, TS 24.501 §7.3.1)
func handlePDUSessionModificationRequest(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
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
		modReq, err := nasCodec.BuildPDUSessionModificationRequest(pduSessionID, 0x01)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionModificationRequest: %v", err))
			return
		}

		inner = modReq
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, inner)
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

// handlePDUSessionReleaseComplete sends a PDU SESSION RELEASE COMPLETE
// (TS 24.501 §6.3.3). The network does not answer, so this is fire-and-forget.
func handlePDUSessionReleaseComplete(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
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
		cmp, err := nasCodec.BuildPDUSessionReleaseComplete(pduSessionID, 0x01)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build PDUSessionReleaseComplete: %v", err))
			return
		}

		inner = cmp
	}

	ulNas, err := nasCodec.BuildULNASTransportExisting(pduSessionID, inner)
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
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID, uplinkOverrides(req),
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

// handleAuthenticationFailure sends an AUTHENTICATION FAILURE in response to an
// Authentication Request (TS 24.501 §5.4.1.3.6). The 5GMM cause defaults to #20
// "MAC failure"; for #21 "synch failure" a valid AUTS is computed from the UE's
// credentials and the last received RAND.
func handleAuthenticationFailure(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		cause := uint8(nasMessage.Cause5GMMMACFailure)
		if req.Cause5GMM != nil {
			cause = *req.Cause5GMM
		}

		var auts []byte

		if cause == nasMessage.Cause5GMMSynchFailure {
			a, err := crypto.ComputeAUTS(ue.K, ue.OPc, ue.Sqn, ue.LastRAND)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("compute AUTS: %v", err))
				return
			}

			auts = a
		}

		pdu, err := nasCodec.BuildAuthenticationFailure(cause, auts)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build AuthenticationFailure: %v", err))
			return
		}

		nasPDU = pdu
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
}

// handleSecurityModeReject sends a SECURITY MODE REJECT in response to a
// Security Mode Command (TS 24.501 §5.4.2.5). The 5GMM cause defaults to #23
// "UE security capabilities mismatch". The message uses the security context in
// use before the SMC procedure (none for initial registration), i.e. plain.
func handleSecurityModeReject(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		cause := uint8(nasMessage.Cause5GMMUESecurityCapabilitiesMismatch)
		if req.Cause5GMM != nil {
			cause = *req.Cause5GMM
		}

		pdu, err := nasCodec.BuildSecurityModeReject(cause)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build SecurityModeReject: %v", err))
			return
		}

		nasPDU = pdu
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "UEContextReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
}

// fiveGSTMSIFromGUTI derives the 5G-S-TMSI IE (for the Initial UE Message)
// from a stored GUTI. The AMF Set ID is a 10-bit field and the AMF Pointer a
// 6-bit field; both are left-aligned into their octets per the NGAP BitString
// encoding.
func fiveGSTMSIFromGUTI(guti *nasType.GUTI5G) *ngap.FiveGSTMSIFromGUTI {
	if guti == nil {
		return nil
	}

	setID := guti.GetAMFSetID()     // 10-bit value, right-aligned
	pointer := guti.GetAMFPointer() // 6-bit value, right-aligned
	tmsi := guti.GetTMSI5G()

	setIDBytes := []byte{byte(setID >> 2), byte((setID & 0x3) << 6)}
	pointerByte := []byte{pointer << 2}

	return &ngap.FiveGSTMSIFromGUTI{
		AMFSetID:   hex.EncodeToString(setIDBytes),
		AMFPointer: hex.EncodeToString(pointerByte),
		FiveGTMSI:  hex.EncodeToString(tmsi[:]),
	}
}

// serviceRequestPDUStatus resolves the PDU Session Status bitmap for a Service
// Request. An explicit hex override (2-byte IE buffer, little-endian) wins;
// otherwise the bitmap is auto-derived from the UE's configured PDU session.
// Returns nil to omit the IE entirely.
func serviceRequestPDUStatus(ue *store.UEContext, req *SendNGAPRequest) (*[16]bool, error) {
	if req.PDUSessionStatus != nil {
		raw, err := hex.DecodeString(*req.PDUSessionStatus)
		if err != nil {
			return nil, err
		}

		var buf [2]byte
		copy(buf[:], raw)
		flags := uint16(buf[0]) | uint16(buf[1])<<8

		var status [16]bool
		for i := range status {
			status[i] = flags&(1<<uint(i)) != 0
		}

		return &status, nil
	}

	var status [16]bool
	if ue.PDUSessionID >= 1 && ue.PDUSessionID <= 15 {
		status[ue.PDUSessionID] = true
	}

	return &status, nil
}

// handleServiceRequest sends a 5GMM Service Request to bring a CM-IDLE UE back
// to CM-CONNECTED (TS 24.501 §5.6.1). It opens a fresh RAN connection (new RAN
// UE NGAP ID + Initial UE Message carrying the 5G-S-TMSI), then drives the
// resulting Initial Context Setup so the AMF re-activates the UE context.
func handleServiceRequest(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest) {
	// A Service Request starts a new RRC/NG connection, so allocate a fresh
	// RAN UE NGAP ID.
	ue.RanUeNgapID = gnb.AllocateRanUeNgapID()

	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
		serviceType := uint8(1) // nasMessage.ServiceTypeData
		if req.ServiceType != nil {
			serviceType = *req.ServiceType
		}

		status, err := serviceRequestPDUStatus(ue, req)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode pdu_session_status: %v", err))
			return
		}

		srPDU, err := nasCodec.BuildServiceRequest(&nasCodec.ServiceRequestOpts{
			ServiceType:      serviceType,
			NgKsi:            ue.NgKsi,
			Guti:             ue.Guti,
			PDUSessionStatus: status,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ServiceRequest: %v", err))
			return
		}

		// Integrity-protect when a security context exists; otherwise send the
		// Service Request plain so it still reaches the AMF (which must reject
		// an unprotected / unknown-UE Service Request).
		if len(ue.Kamf) > 0 {
			nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, srPDU, gonas.SecurityHeaderTypeIntegrityProtected)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
				return
			}
		} else {
			nasPDU = srPDU
		}
	}

	// Initial UE Message with mo-Data establishment cause and the 5G-S-TMSI.
	overrides := initialUEOverrides(req)
	if overrides == nil || overrides.RRCEstablishmentCause == nil {
		moData := int64(4) // RRCEstablishmentCausePresentMoData
		if overrides == nil {
			overrides = &ngap.InitialUEMessageOverrides{}
		}
		overrides.RRCEstablishmentCause = &moData
	}

	ngapMsg := ngap.BuildInitialUEMessageFromState(
		ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID, fiveGSTMSIFromGUTI(ue.Guti), overrides,
	)

	encoded, err := ngap.Encode(ngapMsg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)),
		"InitialContextSetupRequest", "DownlinkNASTransport", "PDUSessionResourceSetupRequest", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for service request response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		// An Error Indication echoes back the AP IDs that were sent (TS 38.413
		// §10.6); it does not assign one, so it must not overwrite the UE's.
		if ie.AmfUeNgapID != nil && ngapResp.MessageType != "ErrorIndication" {
			ue.AmfUeNgapID = *ie.AmfUeNgapID
			gnb.UpdateNGAPIDs(ue.RanUeNgapID, *ie.AmfUeNgapID)
		}

		if ie.NasPDU != nil {
			nasPDUBytes, derr := hex.DecodeString(*ie.NasPDU)
			if derr != nil {
				continue
			}

			nasResp, _ = nasCodec.DecodeSecuredNAS(ue, nasPDUBytes)
		}
	}

	// The AMF reactivates the UE context via Initial Context Setup; acknowledge it.
	if ngapResp.MessageType == "InitialContextSetupRequest" {
		icsResp, berr := ngap.BuildInitialContextSetupResponse(ue.AmfUeNgapID, ue.RanUeNgapID)
		if berr == nil {
			_ = t.Send(icsResp, false)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
}

func sendAndWait(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest, ngapMsg *ngap.NGAPMessage, waitFor ...string) {
	encoded, err := ngap.Encode(ngapMsg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	sendRawAndWait(w, r, gnb, ue, t, req, encoded, waitFor...)
}

func sendUplinkAndWait(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest, nasPDU []byte, waitFor ...string) {
	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	sendRawAndWait(w, r, gnb, ue, t, req, encoded, waitFor...)
}

func sendRawAndWait(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, req *SendNGAPRequest, encoded []byte, waitFor ...string) {
	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)), waitFor...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		// An Error Indication echoes back the AP IDs that were sent (TS 38.413
		// §10.6); it does not assign one, so it must not overwrite the UE's.
		if ie.AmfUeNgapID != nil && ngapResp.MessageType != "ErrorIndication" {
			ue.AmfUeNgapID = *ie.AmfUeNgapID
			gnb.UpdateNGAPIDs(ue.RanUeNgapID, *ie.AmfUeNgapID)
		}

		if ie.NasPDU != nil {
			nasPDUBytes, err := hex.DecodeString(*ie.NasPDU)
			if err != nil {
				continue
			}

			if len(ue.Kamf) > 0 {
				nasResp, _ = nasCodec.DecodeSecuredNAS(ue, nasPDUBytes)
			} else {
				nasResp, _ = nasCodec.Decode(nasPDUBytes)
			}

			if nasResp != nil && nasResp.RAND != "" {
				randBytes, _ := hex.DecodeString(nasResp.RAND)
				autnBytes, _ := hex.DecodeString(nasResp.AUTN)
				ue.LastRAND = randBytes
				ue.LastAUTN = autnBytes
			}

			if nasResp != nil && nasResp.NgKSI != nil && nasResp.SelectedCipheringAlg != nil {
				ue.NgKsi = *nasResp.NgKSI
			}

			if nasResp != nil && nasResp.GUTI != "" {
				gutiBytes, err := hex.DecodeString(nasResp.GUTI)
				if err == nil {
					ue.Guti = nasCodec.ParseGUTI(gutiBytes)
				}
			}
		}
	}

	// A gNB answers an Initial Context Setup Request with a Response. The AMF
	// uses this to re-establish the UE context (e.g. for a mobility/periodic
	// registration update or a service request that reactivates the UE).
	if ngapResp.MessageType == "InitialContextSetupRequest" {
		if icsResp, berr := ngap.BuildInitialContextSetupResponse(ue.AmfUeNgapID, ue.RanUeNgapID); berr == nil {
			_ = t.Send(icsResp, false)
		}
	}

	// A gNB answers a PDU Session Resource Release Command by releasing the
	// resources and returning a Release Response.
	if ngapResp.MessageType == "PDUSessionResourceReleaseCommand" {
		if relResp, berr := ngap.BuildPDUSessionResourceReleaseResponse(ue.AmfUeNgapID, ue.RanUeNgapID); berr == nil {
			_ = t.Send(relResp, false)
		}
	}

	// A gNB answers a UE Context Release Command with a Release Complete.
	if ngapResp.MessageType == "UEContextReleaseCommand" {
		if relComplete, berr := ngap.BuildUEContextReleaseComplete(ue.AmfUeNgapID, ue.RanUeNgapID); berr == nil {
			_ = t.Send(relComplete, false)
		}
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
}
