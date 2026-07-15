// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"strconv"
	"testing"
)

// 5GMM cause values — TS 24.501 §9.11.3.2, Table 9.11.3.2.1.
const (
	cause5GMMUEIdentityCannotBeDerived       = 9
	cause5GMMMACFailure                      = 20
	cause5GMMSynchFailure                    = 21
	cause5GMMUESecurityCapabilitiesMismatch  = 23
	cause5GMMNon5GAuthenticationUnacceptable = 26
	cause5GMMngKSIAlreadyInUse               = 71
	cause5GMMPayloadWasNotForwarded          = 90
	cause5GMMInvalidMandatoryInformation     = 96
	cause5GMMMessageTypeNonExistent          = 97
	cause5GMMProtocolErrorUnspecified        = 111
)

// 5GSM cause values — TS 24.501 §9.11.4.2, Table 9.11.4.2.1.
const (
	cause5GSMMissingOrUnknownDNN                       = 27
	cause5GSMInsufficientResources                     = 26
	cause5GSMUnknownPDUSessionType                     = 28
	cause5GSMPDUSessionTypeIPv4OnlyAllowed             = 50
	cause5GSMPDUSessionTypeIPv6OnlyAllowed             = 51
	cause5GSMMissingOrUnknownDNNInASlice               = 70
	cause5GSMPTIMismatch                               = 47
	cause5GSMInvalidPTIValue                           = 81
	cause5GSMMessageTypeNotCompatibleWithProtocolState = 98
	cause5GSMProtocolErrorUnspecified                  = 111
)

// NGAP radio-network Cause values — TS 38.413 §9.3.1.2.
const (
	causeRadioNetworkReleaseDueToNgranGeneratedReason = 3
	causeRadioNetworkUserInactivity                   = 20
	causeRadioNetworkUnspecified                      = 0
	causeRadioNetworkOutOfRange                       = 250
)

// NAS service types — TS 24.501 §9.11.3.50, Table 9.11.3.50.1.
const (
	serviceTypeSignalling                = 0
	serviceTypeData                      = 1
	serviceTypeMobileTerminatedServices  = 2
	serviceTypeEmergencyServices         = 3
	serviceTypeEmergencyServicesFallback = 4
	serviceTypeHighPriorityAccess        = 5
	serviceTypeOutOfRange                = 7
)

// NGAP message-type names as decoded by internal/ngap/decode.go.
const (
	ngapDownlinkNASTransport             = "DownlinkNASTransport"
	ngapErrorIndication                  = "ErrorIndication"
	ngapInitialContextSetupRequest       = "InitialContextSetupRequest"
	ngapPDUSessionResourceSetupRequest   = "PDUSessionResourceSetupRequest"
	ngapPDUSessionResourceModifyRequest  = "PDUSessionResourceModifyRequest"
	ngapUEContextReleaseCommand          = "UEContextReleaseCommand"
	ngapPDUSessionResourceReleaseCommand = "PDUSessionResourceReleaseCommand"
	ngapNGSetupResponse                  = "NGSetupResponse"
	ngapNGSetupFailure                   = "NGSetupFailure"
	ngapNGResetAcknowledge               = "NGResetAcknowledge"
	ngapHandoverRequest                  = "HandoverRequest"
	ngapHandoverCommand                  = "HandoverCommand"
	ngapHandoverPreparationFailure       = "HandoverPreparationFailure"
	ngapHandoverCancelAcknowledge        = "HandoverCancelAcknowledge"
	ngapPathSwitchRequestAcknowledge     = "PathSwitchRequestAcknowledge"
	ngapPathSwitchRequestFailure         = "PathSwitchRequestFailure"
	ngapDownlinkRANStatusTransfer        = "DownlinkRANStatusTransfer"
)

// NAS message-type names as decoded by internal/nas/decode.go.
const (
	nasAuthenticationRequest         = "authentication_request"
	nasAuthenticationReject          = "authentication_reject"
	nasIdentityRequest               = "identity_request"
	nasPDUSessionReleaseCommand      = "pdu_session_release_command"
	nasRegistrationAccept            = "registration_accept"
	nasRegistrationReject            = "registration_reject"
	nasSecurityModeCommand           = "security_mode_command"
	nasServiceAccept                 = "service_accept"
	nasStatus5GMM                    = "status_5gmm"
	nasDeregistrationAccept          = "deregistration_accept"
	nasServiceReject                 = "service_reject"
	nasPDUSessionEstablishmentAccept = "pdu_session_establishment_accept"
	nasPDUSessionEstablishmentReject = "pdu_session_establishment_reject"
	nasPDUSessionModificationReject  = "pdu_session_modification_reject"
	nas5GSMStatus                    = "5gsm_status"
)

// PDU session types — TS 24.501 §9.11.4.11.
const (
	pduSessionTypeIPv4         = 1
	pduSessionTypeIPv6         = 2
	pduSessionTypeIPv4IPv6     = 3
	pduSessionTypeUnstructured = 4
	pduSessionTypeEthernet     = 5
)

// NGAP Cause, Misc group — TS 38.413 §9.3.1.2.
const (
	causePresentMisc           = "misc"
	causeMiscUnknownPLMNOrSNPN = 4
)

// NGAP Cause, Protocol group — TS 38.413 §9.3.1.2 (CauseProtocol).
const (
	causeProtocolTransferSyntaxError = 0
)

// NGAP procedure codes — TS 38.413 §9.4.7 (Constant Definitions).
const (
	ngapProcedureCodeUplinkNASTransport = 46
)

// 5GS identity types — TS 24.501 §9.11.3.3, Table 9.11.3.3.1.
const identityTypeSUCI = "1"

// NAS registration types — TS 24.501 §9.11.3.7, Table 9.11.3.7.1.
const (
	registrationTypeInitial   = 1
	registrationTypeMobility  = 2
	registrationTypePeriodic  = 3
	registrationTypeEmergency = 4
)

// NGAP RRC establishment cause — TS 38.413 §9.3.1.111.
const (
	rrcEstablishmentCauseHighPriorityAccess = 1
	rrcEstablishmentCauseMoVoiceCall        = 5
	rrcEstablishmentCauseOutOfRange         = 99
)

func assertNASCause(t *testing.T, body []byte, path string, want int) {
	t.Helper()

	if want == 0 {
		return
	}

	if got := jsonGet(body, path); got != strconv.Itoa(want) {
		t.Errorf("%s = %q, want %d\n  body: %s", path, got, want, body)
	}
}

func ngapCause(body []byte, responseKey string) (string, int) {
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		return "", 0
	}

	resp, ok := top[responseKey].(map[string]any)
	if !ok {
		return "", 0
	}

	ies, ok := resp["ies"].([]any)
	if !ok {
		return "", 0
	}

	for _, ie := range ies {
		iem, ok := ie.(map[string]any)
		if !ok {
			continue
		}

		cause, ok := iem["cause"].(map[string]any)
		if !ok {
			continue
		}

		present, _ := cause["present"].(string)
		if v, ok := cause[present].(float64); ok {
			return present, int(v)
		}

		return present, 0
	}

	return "", 0
}

func assertNGAPCauseMisc(t *testing.T, body []byte, responseKey string, want int) {
	t.Helper()

	if want == 0 {
		return
	}

	group, val := ngapCause(body, responseKey)
	if group != causePresentMisc || val != want {
		t.Errorf("%s NGAP cause = (%q, %d), want (%q, %d)\n  body: %s",
			responseKey, group, val, causePresentMisc, want, body)
	}
}

// Sequential allocation packs n values into a span of n-1, so a far wider span is evidence of unpredictable generation.
func assertUnpredictableTMSIs(t *testing.T, values []uint64, name, cite string) {
	t.Helper()

	if len(values) < 2 {
		t.Fatalf("need at least 2 %ss to judge allocation, got %d", name, len(values))
	}

	min, max := values[0], values[0]

	for _, v := range values[1:] {
		if v < min {
			min = v
		}

		if v > max {
			max = v
		}
	}

	if max-min < 1000 {
		t.Errorf("%ss span only %d across %d allocations; allocation looks sequential/predictable (%s)",
			name, max-min, len(values), cite)
	}
}
