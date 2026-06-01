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
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported message_type: %s", req.MessageType))
	}
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

		ngapMsg := ngap.BuildInitialUEMessageFromState(
			ue.RanUeNgapID, nasPDU,
			gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID, nil, initialUEOverrides(req),
		)
		sendAndWait(w, r, gnb, ue, t, ngapMsg, "DownlinkNASTransport", "ErrorIndication")

		return
	}

	regType := uint8(nasCodec.RegistrationTypeInitial)
	if req.RegistrationType != nil {
		regType = *req.RegistrationType
	}

	nasPDU, err := nasCodec.BuildRegistrationRequest(&nasCodec.RegistrationRequestOpts{
		RegistrationType: regType,
		Suci:             ue.Suci,
		Guti:             ue.Guti,
		SecurityCap:      ue.UeSecurityCapability,
		NgKsi:            7,
		Overrides:        req,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build NAS RegistrationRequest: %v", err))
		return
	}

	ngapMsg := ngap.BuildInitialUEMessageFromState(
		ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GnbID, nil, initialUEOverrides(req),
	)
	sendAndWait(w, r, gnb, ue, t, ngapMsg, "DownlinkNASTransport", "ErrorIndication")
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
		regReqPDU, err := nasCodec.BuildRegistrationRequest(&nasCodec.RegistrationRequestOpts{
			RegistrationType: nasCodec.RegistrationTypeInitial,
			Suci:             ue.Suci,
			Guti:             ue.Guti,
			SecurityCap:      ue.UeSecurityCapability,
			NgKsi:            ue.NgKsi,
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

	ngapResp, err := t.WaitForMessage(ctx, "PDUSessionResourceSetupRequest", "DownlinkNASTransport", "ErrorIndication")
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

	pduSetupResp, err := ngap.BuildPDUSessionResourceSetupResponse(ue.AmfUeNgapID, ue.RanUeNgapID)
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
		deregPDU, err := nasCodec.BuildDeregistrationRequest(&nasCodec.DeregistrationRequestOpts{
			Guti:  ue.Guti,
			Suci:  &ue.Suci,
			NgKsi: ue.NgKsi,
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

	ngapResp, err := t.WaitForMessage(ctx, "UEContextReleaseCommand", "DownlinkNASTransport", "ErrorIndication")
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

	ngapResp, err := t.WaitForMessage(ctx, "UEContextReleaseCommand", "ErrorIndication")
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

// fiveGSTMSIFromGUTI derives the 5G-S-TMSI IE (for the Initial UE Message)
// from a stored GUTI. The AMF Set ID is a 10-bit field and the AMF Pointer a
// 6-bit field; both are left-aligned into their octets per the NGAP BitString
// encoding.
func fiveGSTMSIFromGUTI(guti *nasType.GUTI5G) *ngap.FiveGSTMSIFromGUTI {
	if guti == nil {
		return nil
	}

	setID := guti.GetAMFSetID() // 10-bit value, right-aligned
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

	ngapResp, err := t.WaitForMessage(ctx,
		"InitialContextSetupRequest", "DownlinkNASTransport", "PDUSessionResourceSetupRequest", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for service request response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		if ie.AmfUeNgapID != nil {
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

func sendAndWait(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, ngapMsg *ngap.NGAPMessage, waitFor ...string) {
	encoded, err := ngap.Encode(ngapMsg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("NGAP encode: %v", err))
		return
	}

	sendRawAndWait(w, r, gnb, ue, t, encoded, waitFor...)
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

	sendRawAndWait(w, r, gnb, ue, t, encoded, waitFor...)
}

func sendRawAndWait(w http.ResponseWriter, r *http.Request, gnb *store.GnBContext, ue *store.UEContext, t *transport.SCTPTransport, encoded []byte, waitFor ...string) {
	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, waitFor...)
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		if ie.AmfUeNgapID != nil {
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

	writeJSON(w, http.StatusOK, SendNGAPResponse{
		NGAP: ngapResp,
		NAS:  nasResp,
	})
}
