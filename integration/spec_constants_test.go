//go:build integration

// Human-readable names for the 3GPP coded values used across the integration
// tests, so assertions and request bodies read in terms of the spec rather than
// raw integers. Values are taken from the referenced TS 24.501 / TS 38.413
// tables.

package integration_test

import (
	"strconv"
	"testing"
)

// 5GMM cause values — TS 24.501 §9.11.3.2, Table 9.11.3.2.1.
const (
	cause5GMMPayloadWasNotForwarded   = 90
	cause5GMMProtocolErrorUnspecified = 111
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
	ngapDownlinkNASTransport          = "DownlinkNASTransport"
	ngapErrorIndication               = "ErrorIndication"
	ngapInitialContextSetupRequest    = "InitialContextSetupRequest"
	ngapPDUSessionResourceSetupRequest = "PDUSessionResourceSetupRequest"
	ngapUEContextReleaseCommand       = "UEContextReleaseCommand"
	ngapNGSetupResponse               = "NGSetupResponse"
	ngapNGSetupFailure                = "NGSetupFailure"
)

// NAS message-type names as decoded by the server (internal/nas/decode.go),
// used as assertion targets for nas.message_type / nas.inner_nas_message_type.
const (
	nasAuthenticationRequest         = "authentication_request"
	nasAuthenticationReject          = "authentication_reject"
	nasRegistrationAccept            = "registration_accept"
	nasRegistrationReject            = "registration_reject"
	nasSecurityModeCommand           = "security_mode_command"
	nasServiceAccept                 = "service_accept"
	nasStatus5GMM                    = "status_5gmm"
	nasDeregistrationAccept          = "deregistration_accept"
	nasPDUSessionEstablishmentAccept = "pdu_session_establishment_accept"
	nasPDUSessionEstablishmentReject = "pdu_session_establishment_reject"
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
