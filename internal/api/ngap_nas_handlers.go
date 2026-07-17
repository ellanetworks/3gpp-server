// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
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
	"github.com/free5gc/ngap/ngapType"
)

func uplinkOverrides(req *SendNGAPRequest) *ngap.UplinkNASTransportOverrides {
	if req.AmfUeNgapIDOverride == nil && req.RanUeNgapIDOverride == nil {
		return nil
	}

	return &ngap.UplinkNASTransportOverrides{
		AmfUeNgapID: req.AmfUeNgapIDOverride,
		RanUeNgapID: req.RanUeNgapIDOverride,
	}
}

func securityOpts(req *SendNGAPRequest) []nasCodec.EncodeOption {
	var opts []nasCodec.EncodeOption
	if req.CorruptMAC {
		opts = append(opts, nasCodec.WithCorruptMAC())
	}

	if req.NASCountOverride != nil {
		opts = append(opts, nasCodec.WithNASCountOverride(*req.NASCountOverride))
	}

	return opts
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

func handleRegistrationRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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

		ngapMsg, err := ngap.BuildInitialUEMessageFromState(
			ue.RanUeNgapID, nasPDU,
			gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, nil, initialUEOverrides(req),
		)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("build initial ue message: %v", err))
			return
		}

		sendAndWait(w, r, gnb, ue, t, req, ngapMsg, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")

		return
	}

	regType := uint8(nasCodec.RegistrationTypeInitial)
	if req.RegistrationType != nil {
		regType = *req.RegistrationType
	}

	// A mobility or periodic update reuses its security context (TS 24.501 §5.5.1.3).
	mobilityOrPeriodic := regType == nasCodec.RegistrationTypeMobility || regType == nasCodec.RegistrationTypePeriodic
	secured := mobilityOrPeriodic && len(ue.Kamf) > 0

	ngKsi := ksiNoKey
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
		nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, nasPDU, gonas.SecurityHeaderTypeIntegrityProtected, securityOpts(req)...)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	if req.ExistingConnection {
		sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "DownlinkNASTransport", "ErrorIndication")
		return
	}

	ngapMsg, err := ngap.BuildInitialUEMessageFromState(
		ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, nil, initialUEOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("build initial ue message: %v", err))
		return
	}

	sendAndWait(w, r, gnb, ue, t, req, ngapMsg, "DownlinkNASTransport", "InitialContextSetupRequest", "ErrorIndication")
}

func handleAuthenticationResponse(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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
			resStar = make([]byte, 16)
		} else {
			akaResult, err := crypto.Compute5GAKA(ue.K, ue.OPc, ue.Sqn, ue.Supi, ue.Snn, ue.LastRAND, ue.LastAUTN)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("5G-AKA: %v", err))
				return
			}

			ue.Kamf = akaResult.Kamf
			resStar = akaResult.RESStar
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

func handleSecurityModeComplete(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	if req.RawNASPDU != nil {
		raw, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("decode raw_nas_pdu: %v", err))
			return
		}

		nasPDU = raw
	} else {
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
			gonas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, securityOpts(req)...)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
			return
		}
	}

	sendUplinkAndWait(w, r, gnb, ue, t, req, nasPDU, "InitialContextSetupRequest", "DownlinkNASTransport", "ErrorIndication")
}

func handleRegistrationComplete(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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

func handleDeregistrationRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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

func handleUEContextReleaseRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
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

func handleIdentityResponse(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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

func handleAuthenticationFailure(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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

func handleSecurityModeReject(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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

// NGAP BitString left-aligns the 10-bit Set ID and 6-bit Pointer into their octets.
func fiveGSTMSIFromGUTI(guti *nasType.GUTI5G) *ngap.FiveGSTMSIFromGUTI {
	if guti == nil {
		return nil
	}

	setID := guti.GetAMFSetID()
	pointer := guti.GetAMFPointer()
	tmsi := guti.GetTMSI5G()

	setIDBytes := []byte{byte(setID >> 2), byte((setID & 0x3) << 6)}
	pointerByte := []byte{pointer << 2}

	return &ngap.FiveGSTMSIFromGUTI{
		AMFSetID:   hex.EncodeToString(setIDBytes),
		AMFPointer: hex.EncodeToString(pointerByte),
		FiveGTMSI:  hex.EncodeToString(tmsi[:]),
	}
}

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

func handleServiceRequest(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
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
		serviceType := nasMessage.ServiceTypeData
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

		if len(ue.Kamf) > 0 {
			nasPDU, err = nasCodec.EncodeNasPduWithSecurity(ue, srPDU, gonas.SecurityHeaderTypeIntegrityProtected, securityOpts(req)...)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("NAS security encode: %v", err))
				return
			}
		} else {
			nasPDU = srPDU
		}
	}

	overrides := initialUEOverrides(req)
	if overrides == nil || overrides.RRCEstablishmentCause == nil {
		moData := int64(ngapType.RRCEstablishmentCausePresentMoData)
		if overrides == nil {
			overrides = &ngap.InitialUEMessageOverrides{}
		}
		overrides.RRCEstablishmentCause = &moData
	}

	ngapMsg, err := ngap.BuildInitialUEMessageFromState(
		ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, fiveGSTMSIFromGUTI(ue.Guti), overrides,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("build initial ue message: %v", err))
		return
	}

	encoded, err := ngap.Encode(ngapMsg)
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
		"InitialContextSetupRequest", "DownlinkNASTransport", "PDUSessionResourceSetupRequest", "ErrorIndication")
	if err != nil {
		writeError(w, http.StatusGatewayTimeout, fmt.Sprintf("waiting for service request response: %v", err))
		return
	}

	var nasResp *nasCodec.NASResponse

	for _, ie := range ngapResp.IEs {
		// An Error Indication echoes the AP IDs it was sent; it assigns none.
		if ie.AmfUeNgapID != nil && ngapResp.MessageType != "ErrorIndication" {
			ue.AmfUeNgapID = *ie.AmfUeNgapID
		}

		if ie.NasPDU != nil {
			nasPDUBytes, derr := hex.DecodeString(*ie.NasPDU)
			if derr != nil {
				continue
			}

			nasResp, _ = nasCodec.DecodeSecuredNAS(ue, nasPDUBytes)
		}
	}

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

func handleInjectNAS(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	var nasPDU []byte

	switch {
	case req.ReplayLast:
		if len(ue.LastUplinkNAS) == 0 {
			writeError(w, http.StatusBadRequest, "no prior uplink to replay")
			return
		}

		nasPDU = ue.LastUplinkNAS
	case req.RawNASPDU != nil:
		decoded, err := hex.DecodeString(*req.RawNASPDU)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("raw_nas_pdu must be hex: %v", err))
			return
		}

		nasPDU = decoded
	default:
		writeError(w, http.StatusBadRequest, "inject_nas requires raw_nas_pdu or replay_last")
		return
	}

	encoded, err := ngap.BuildUplinkNASTransport(
		ue.AmfUeNgapID, ue.RanUeNgapID, nasPDU,
		gnb.MCC, gnb.MNC, gnb.TAC, gnb.GNBID, uplinkOverrides(req),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build UplinkNASTransport: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), waitTimeout(req.TimeoutMs))
	defer cancel()

	ngapResp, err := t.WaitForMessage(ctx, "DownlinkNASTransport", "ErrorIndication", "UEContextReleaseCommand")
	if err != nil {
		writeJSON(w, http.StatusOK, SendNGAPResponse{})
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func handleUECapabilityInfo(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	radioCap := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	if req.UERadioCapability != nil {
		decoded, err := hex.DecodeString(*req.UERadioCapability)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("ue_radio_capability must be hex: %v", err))
			return
		}

		radioCap = decoded
	}

	encoded, err := ngap.BuildUERadioCapabilityInfoIndication(effectiveAmfID(req, ue), effectiveRanID(req, ue), radioCap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build UERadioCapabilityInfoIndication: %v", err))
		return
	}

	if err := t.Send(encoded, false); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("SCTP send: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()

	ngapResp, err := t.WaitForMessageMatching(ctx, ueNGAPMatcher(effectiveRanID(req, ue), effectiveAmfID(req, ue)), "ErrorIndication")
	if err != nil {
		writeJSON(w, http.StatusOK, SendNGAPResponse{})
		return
	}

	writeJSON(w, http.StatusOK, SendNGAPResponse{NGAP: ngapResp})
}

func handleErrorIndication(w http.ResponseWriter, r *http.Request, gnb *store.GNBContext, ue *store.UEContext, t *transport.NGAPTransport, req *SendNGAPRequest) {
	encoded, err := ngap.BuildErrorIndication(effectiveAmfID(req, ue), effectiveRanID(req, ue), causeRadioNetworkUnspecified)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("build ErrorIndication: %v", err))
		return
	}

	sendRawAndWait(w, r, gnb, ue, t, req, encoded, "UEContextReleaseCommand", "ErrorIndication")
}
