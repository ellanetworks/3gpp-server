//go:build integration

// Human-readable names for the 3GPP coded values used across the integration
// tests, so assertions and request bodies read in terms of the spec rather than
// raw integers. Values are taken from the referenced TS 24.501 / TS 38.413
// tables.

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
	cause5GMMProtocolErrorUnspecified        = 111
)

// 5GSM cause values — TS 24.501 §9.11.4.2, Table 9.11.4.2.1.
const (
	cause5GSMUnknownPDUSessionType                     = 28
	cause5GSMMessageTypeNotCompatibleWithProtocolState = 98
	cause5GSMProtocolErrorUnspecified                  = 111
)

// NGAP radio-network Cause values — TS 38.413 §9.3.1.2.
const (
	causeRadioNetworkReleaseDueToNgranGeneratedReason = 3
	causeRadioNetworkUserInactivity                   = 20
	causeRadioNetworkUnspecified                      = 0

	// causeRadioNetworkOutOfRange is deliberately outside the enumerated
	// radio-network Cause range, for robustness fuzzing.
	causeRadioNetworkOutOfRange = 250
)

// NAS service types — TS 24.501 §9.11.3.50, Table 9.11.3.50.1.
const (
	serviceTypeSignalling                = 0
	serviceTypeData                      = 1
	serviceTypeMobileTerminatedServices  = 2
	serviceTypeEmergencyServices         = 3
	serviceTypeEmergencyServicesFallback = 4
	serviceTypeHighPriorityAccess        = 5

	// serviceTypeOutOfRange is an unassigned service-type value, for fuzzing.
	serviceTypeOutOfRange = 7
)

// NGAP message-type names as decoded by the server (internal/ngap/decode.go),
// used as assertion targets for ngap.message_type.
const (
	ngapDownlinkNASTransport             = "DownlinkNASTransport"
	ngapErrorIndication                  = "ErrorIndication"
	ngapInitialContextSetupRequest       = "InitialContextSetupRequest"
	ngapPDUSessionResourceSetupRequest   = "PDUSessionResourceSetupRequest"
	ngapUEContextReleaseCommand          = "UEContextReleaseCommand"
	ngapPDUSessionResourceReleaseCommand = "PDUSessionResourceReleaseCommand"
	ngapNGSetupResponse                  = "NGSetupResponse"
	ngapNGSetupFailure                   = "NGSetupFailure"
	ngapNGResetAcknowledge               = "NGResetAcknowledge"
	ngapHandoverRequest                  = "HandoverRequest"
	ngapHandoverCommand                  = "HandoverCommand"
	ngapHandoverPreparationFailure       = "HandoverPreparationFailure"
)

// NAS message-type names as decoded by the server (internal/nas/decode.go),
// used as assertion targets for nas.message_type / nas.inner_nas_message_type.
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
)

// NGAP Cause, Misc group — TS 38.413 §9.3.1.2.
const (
	causePresentMisc           = "misc"
	causeMiscUnknownPLMNOrSNPN = 4
)

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

	// rrcEstablishmentCauseOutOfRange is outside the enumerated range, for fuzzing.
	rrcEstablishmentCauseOutOfRange = 99
)

// assertNASCause checks that the NAS cause at the given JSON path equals the
// expected (named) value. A want of 0 means "do not check".
func assertNASCause(t *testing.T, body []byte, path string, want int) {
	t.Helper()

	if want == 0 {
		return
	}

	if got := jsonGet(body, path); got != strconv.Itoa(want) {
		t.Errorf("%s = %q, want %d\n  body: %s", path, got, want, body)
	}
}

// ngapCause extracts the NGAP Cause carried in the IE list of the response
// object at responseKey (e.g. "ng_setup_response"). It returns the Cause group
// ("misc", "radioNetwork", …) and the integer value within that group, or
// ("", 0) if no Cause IE is present.
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

// assertNGAPCauseMisc checks the response carries an NGAP Misc Cause equal to
// the expected value. A want of 0 means "do not check".
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
