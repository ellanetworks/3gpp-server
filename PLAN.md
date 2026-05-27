# 3gpp-server Implementation Plan

## Overview

A standalone Go HTTP server that translates JSON to/from NGAP/NAS 3GPP messages over SCTP, with crypto utilities. Designed to be driven by an AI agent for conformance testing, fuzzing, and security assessment of 5G core networks.

The JSON schema mirrors NGAP/NAS IEs 1:1 so the caller controls which IEs are present, their order, criticality, and values — enabling both correct procedures and deliberate deviations. Every message type supports a `raw_nas_pdu` escape hatch for sending arbitrary bytes.

**Goals:**
1. Full coverage of every NGAP message (TS 38.413) and every NAS message (TS 24.501).
2. Enable comprehensive security testing of 5G core networks — not just conformance, but adversarial fuzzing.

## Security Testing Objectives

Once message coverage is complete, 3gpp-server enables the following test campaigns against a target AMF:

- **Protocol state machine fuzzing.** Send messages in wrong order, repeat messages, interleave procedures. Every unexpected state transition is a potential bug.
- **IE boundary testing.** For every IE in every message: minimum/maximum length, zero length, one byte over/under, all zeros, all 0xff. Systematic coverage of every field in every message.
- **Credential and identity attacks.** Wrong K/OPc for a SUCI, RES* from subscriber A on subscriber B's session, replayed RAND/AUTN, GUTI belonging to a different UE.
- **Concurrency and race conditions.** Hundreds of simultaneous registrations, same SUCI from multiple gNBs, deregistration during PDU session setup, SCTP disconnect mid-handshake.
- **Resource exhaustion.** Thousands of half-open registrations, maximum PDU sessions, largest possible IEs, timer pile-up from never completing procedures.
- **Replay and downgrade attacks.** Replayed SecurityModeComplete with reset ULCount, RegistrationRequest claiming null-only algorithms (EA0/IA0), integrity MAC computed with wrong key.
- **Cross-session contamination.** Register, deregister, re-register with different credentials. Verify no state leaks: old GUTI rejected, old keys rejected, old PDU session IDs not reused.
- **Negative testing at scale.** For every message type, generate thousands of variants with randomized IE values. The AMF must never crash, hang, or leak memory. Any silent drop is a spec violation.

## Dependencies and Limitations

We use free5gc libraries (aper, ngap, nas, util) for encoding/decoding. These are Release 15 (2018) — the specs are now on Release 18. This means:

- IEs added in R16-R18 don't exist in the typed API
- The APER encoder enforces ASN.1 constraints, preventing intentionally malformed NGAP messages
- Fixed-size structs (e.g. `GUTI5G.Octet[11]`) prevent oversized field testing through the typed path

**Mitigation (current):** `raw_nas_pdu` bypasses the NAS encoder entirely. A future `raw_ngap_pdu` override and the Phase 15 raw SCTP endpoint will complete the bypass at every layer.

**Future: custom NGAP/NAS codec.** Once we've implemented all phases and have deep knowledge of which messages and IEs matter most, replace free5gc incrementally — one message type at a time, starting with whichever is most limiting. This is not a near-term priority; the raw bypass layers cover fuzzing needs in the meantime.

## Source Code Reference

Porting from `/home/guillaume/code/core2/internal/tester/`.

## 3GPP Spec Cross-Reference

Every message implementation must be cross-referenced against the 3GPP spec PDFs in the repo root and free5gc types:

1. Look up the IE table in TS 38.413 §9.2.x (NGAP) or TS 24.501 §8.x (NAS)
2. Cross-reference against free5gc structs
3. Verify all IEs (mandatory and optional) have encode and decode paths

## Completed

- **Phases 1-3:** gNB lifecycle, UE lifecycle, full registration flow (NGSetup, InitialUEMessage, DownlinkNASTransport, UplinkNASTransport, InitialContextSetupRequest/Response, RegistrationRequest/Accept/Complete, AuthenticationRequest/Response, SecurityModeCommand/Complete, 5G-AKA, NAS security)
- **Phase 4:** PDU session establishment (PDUSessionEstablishmentRequest/Accept, PDUSessionResourceSetupRequest/Response, ULNASTransport/DLNASTransport with 5GSM payloads)

97 integration tests. Full registration + PDU session via the API validated against Ella Core.

## Phase 5: Deregistration + UE Context Release

| Direction | NGAP | NAS | Spec |
|-----------|------|-----|------|
| UE→AMF | UplinkNASTransport | DeregistrationRequest (UE-originated) | TS 24.501 §8.2.12 |
| AMF→UE | DownlinkNASTransport | DeregistrationAccept | TS 24.501 §8.2.13 |
| AMF→UE | DownlinkNASTransport | DeregistrationRequest (network-initiated) | TS 24.501 §8.2.14 |
| UE→AMF | UplinkNASTransport | DeregistrationAccept (network-initiated) | TS 24.501 §8.2.15 |
| AMF→gNB | UEContextReleaseCommand | — | TS 38.413 §9.2.2.5 |
| gNB→AMF | UEContextReleaseComplete | — | TS 38.413 §9.2.2.6 |
| gNB→AMF | UEContextReleaseRequest | — | TS 38.413 §9.2.2.4 |

## Phase 6: Service Request + Paging

| Direction | NGAP | NAS | Spec |
|-----------|------|-----|------|
| UE→AMF | InitialUEMessage | ServiceRequest | TS 24.501 §8.2.16 |
| AMF→UE | DownlinkNASTransport | ServiceAccept | TS 24.501 §8.2.17 |
| AMF→UE | DownlinkNASTransport | ServiceReject | TS 24.501 §8.2.18 |
| AMF→gNB | Paging | — | TS 38.413 §9.2.4.1 |

## Phase 7: Identity + Configuration + Notification

| Direction | NGAP | NAS | Spec |
|-----------|------|-----|------|
| AMF→UE | DownlinkNASTransport | IdentityRequest | TS 24.501 §8.2.21 |
| UE→AMF | UplinkNASTransport | IdentityResponse | TS 24.501 §8.2.22 |
| AMF→UE | DownlinkNASTransport | ConfigurationUpdateCommand | TS 24.501 §8.2.19 |
| UE→AMF | UplinkNASTransport | ConfigurationUpdateComplete | TS 24.501 §8.2.20 |
| AMF→UE | DownlinkNASTransport | Notification | TS 24.501 §8.2.23 |
| UE→AMF | UplinkNASTransport | NotificationResponse | TS 24.501 §8.2.24 |
| UE→AMF | UplinkNASTransport | SecurityModeReject | TS 24.501 §8.2.27 |

## Phase 8: PDU Session Modification + Release

| Direction | NGAP | NAS | Spec |
|-----------|------|-----|------|
| UE→AMF | UplinkNASTransport | PDUSessionModificationRequest | TS 24.501 §8.3.7 |
| AMF→UE | DownlinkNASTransport | PDUSessionModificationCommand | TS 24.501 §8.3.9 |
| UE→AMF | UplinkNASTransport | PDUSessionModificationComplete | TS 24.501 §8.3.10 |
| AMF→UE | DownlinkNASTransport | PDUSessionModificationReject | TS 24.501 §8.3.8 |
| UE→AMF | UplinkNASTransport | PDUSessionModificationCommandReject | TS 24.501 §8.3.11 |
| UE→AMF | UplinkNASTransport | PDUSessionReleaseRequest | TS 24.501 §8.3.12 |
| AMF→UE | DownlinkNASTransport | PDUSessionReleaseCommand | TS 24.501 §8.3.14 |
| UE→AMF | UplinkNASTransport | PDUSessionReleaseComplete | TS 24.501 §8.3.15 |
| AMF→UE | DownlinkNASTransport | PDUSessionReleaseReject | TS 24.501 §8.3.13 |
| AMF→gNB | PDUSessionResourceReleaseCommand | — | TS 38.413 §9.2.1.4 |
| gNB→AMF | PDUSessionResourceReleaseResponse | — | TS 38.413 §9.2.1.5 |
| AMF→gNB | PDUSessionResourceModifyRequest | — | TS 38.413 §9.2.1.6 |
| gNB→AMF | PDUSessionResourceModifyResponse | — | TS 38.413 §9.2.1.7 |
| gNB→AMF | PDUSessionResourceNotify | — | TS 38.413 §9.2.1.8 |
| gNB→AMF | PDUSessionResourceModifyIndication | — | TS 38.413 §9.2.1.9 |
| AMF→gNB | PDUSessionResourceModifyConfirm | — | TS 38.413 §9.2.1.10 |

## Phase 9: Authentication Extensions

| Direction | NGAP | NAS | Spec |
|-----------|------|-----|------|
| UE→AMF | UplinkNASTransport | AuthenticationFailure | TS 24.501 §8.2.4 |
| AMF→UE | DownlinkNASTransport | AuthenticationResult | TS 24.501 §8.2.3 |
| AMF→UE | DownlinkNASTransport | AuthenticationReject | TS 24.501 §8.2.5 |
| — | — | 5GMM STATUS | TS 24.501 §8.2.29 |
| — | — | 5GSM STATUS | TS 24.501 §8.3.16 |
| UE→AMF | UplinkNASTransport | ControlPlaneServiceRequest | TS 24.501 §8.2.30 |

## Phase 10: Handover

| Direction | NGAP | Spec |
|-----------|------|------|
| gNB→AMF | HandoverRequired | TS 38.413 §9.2.3.1 |
| AMF→gNB | HandoverCommand | TS 38.413 §9.2.3.2 |
| AMF→gNB | HandoverPreparationFailure | TS 38.413 §9.2.3.3 |
| AMF→gNB(target) | HandoverRequest | TS 38.413 §9.2.3.4 |
| gNB→AMF | HandoverRequestAcknowledge | TS 38.413 §9.2.3.5 |
| gNB→AMF | HandoverFailure | TS 38.413 §9.2.3.6 |
| gNB→AMF | HandoverNotify | TS 38.413 §9.2.3.7 |
| gNB→AMF | PathSwitchRequest | TS 38.413 §9.2.3.8 |
| AMF→gNB | PathSwitchRequestAcknowledge | TS 38.413 §9.2.3.9 |
| AMF→gNB | PathSwitchRequestFailure | TS 38.413 §9.2.3.10 |
| gNB→AMF | HandoverCancel | TS 38.413 §9.2.3.11 |
| AMF→gNB | HandoverCancelAcknowledge | TS 38.413 §9.2.3.12 |
| gNB→AMF | HandoverSuccess | TS 38.413 §9.2.3.13 |
| gNB→AMF | UplinkRANStatusTransfer | TS 38.413 §9.2.3.14 |
| AMF→gNB | DownlinkRANStatusTransfer | TS 38.413 §9.2.3.15 |
| gNB→AMF | UplinkRANEarlyStatusTransfer | TS 38.413 §9.2.3.16 |
| AMF→gNB | DownlinkRANEarlyStatusTransfer | TS 38.413 §9.2.3.17 |

## Phase 11: Interface Management

| Direction | NGAP | Spec |
|-----------|------|------|
| gNB→AMF | RANConfigurationUpdate | TS 38.413 §9.2.6.7 |
| AMF→gNB | RANConfigurationUpdateAcknowledge | TS 38.413 §9.2.6.8 |
| AMF→gNB | RANConfigurationUpdateFailure | TS 38.413 §9.2.6.9 |
| AMF→gNB | AMFConfigurationUpdate | TS 38.413 §9.2.6.10 |
| gNB→AMF | AMFConfigurationUpdateAcknowledge | TS 38.413 §9.2.6.11 |
| gNB→AMF | AMFConfigurationUpdateFailure | TS 38.413 §9.2.6.12 |
| both | NGReset | TS 38.413 §9.2.6.4 |
| both | NGResetAcknowledge | TS 38.413 §9.2.6.5 |
| both | ErrorIndication | TS 38.413 §9.2.6.13 |
| AMF→gNB | AMFStatusIndication | TS 38.413 §9.2.6.14 |
| AMF→gNB | OverloadStart | TS 38.413 §9.2.6.15 |
| AMF→gNB | OverloadStop | TS 38.413 §9.2.6.16 |

## Phase 12: UE Context Management (Extended)

| Direction | NGAP | Spec |
|-----------|------|------|
| AMF→gNB | UEContextModificationRequest | TS 38.413 §9.2.2.7 |
| gNB→AMF | UEContextModificationResponse | TS 38.413 §9.2.2.8 |
| gNB→AMF | UEContextModificationFailure | TS 38.413 §9.2.2.9 |
| gNB→AMF | RRCInactiveTransitionReport | TS 38.413 §9.2.2.10 |
| gNB→AMF | ConnectionEstablishmentIndication | TS 38.413 §9.2.2.11 |
| AMF→gNB | AMFCPRelocationIndication | TS 38.413 §9.2.2.12 |
| gNB→AMF | RANCPRelocationIndication | TS 38.413 §9.2.2.13 |
| AMF→gNB | RetrieveUEInformation | TS 38.413 §9.2.2.14 |
| gNB→AMF | UEInformationTransfer | TS 38.413 §9.2.2.15 |
| AMF→gNB | UEContextSuspendRequest | TS 38.413 §9.2.2.16 |
| gNB→AMF | UEContextSuspendResponse/Failure | TS 38.413 §9.2.2.17-18 |
| AMF→gNB | UEContextResumeRequest | TS 38.413 §9.2.2.19 |
| gNB→AMF | UEContextResumeResponse/Failure | TS 38.413 §9.2.2.20-21 |

## Phase 13: Remaining NGAP Procedures

| Direction | NGAP | Spec |
|-----------|------|------|
| gNB→AMF | UplinkRANConfigurationTransfer | TS 38.413 §9.2.7.1 |
| AMF→gNB | DownlinkRANConfigurationTransfer | TS 38.413 §9.2.7.2 |
| AMF→gNB | WriteReplaceWarningRequest | TS 38.413 §9.2.8.1 |
| gNB→AMF | WriteReplaceWarningResponse | TS 38.413 §9.2.8.2 |
| AMF→gNB | PWSCancelRequest | TS 38.413 §9.2.8.3 |
| gNB→AMF | PWSCancelResponse | TS 38.413 §9.2.8.4 |
| gNB→AMF | PWSRestartIndication | TS 38.413 §9.2.8.5 |
| gNB→AMF | PWSFailureIndication | TS 38.413 §9.2.8.6 |
| gNB→AMF | NASNonDeliveryIndication | TS 38.413 §9.2.5.4 |
| AMF→gNB | RerouteNASRequest | TS 38.413 §9.2.5.5 |
| both | NRPPaTransport (UL/DL) | TS 38.413 §9.2.9.1-2 |
| both | LocationReport/Control | TS 38.413 §9.2.11.1-3 |
| both | UETNLABindingRelease | TS 38.413 §9.2.12.1 |
| AMF→gNB | UERadioCapabilityCheckRequest | TS 38.413 §9.2.13.1 |
| gNB→AMF | UERadioCapabilityCheckResponse | TS 38.413 §9.2.13.2 |
| gNB→AMF | UERadioCapabilityInfoIndication | TS 38.413 §9.2.13.3 |
| both | SecondaryRATDataUsageReport | TS 38.413 §9.2.14.1 |
| AMF→gNB | TraceStart / DeactivateTrace | TS 38.413 §9.2.10.1-2 |
| gNB→AMF | TraceFailureIndication / CellTrafficTrace | TS 38.413 §9.2.10.3-4 |
| AMF→gNB | MulticastGroupPaging | TS 38.413 §9.2.4.2 |
| AMF→gNB | BroadcastSession* | TS 38.413 §9.2.16.1-8 |
| AMF→gNB | MulticastSession* | TS 38.413 §9.2.17.1-4 |
| AMF→gNB | TimingSynchronisationStatus* | TS 38.413 §9.2.18.1-2 |

## Phase 14: NAS Extensions

| Direction | NAS | Spec |
|-----------|-----|------|
| AMF→UE | PDUSessionAuthenticationCommand | TS 24.501 §8.3.4 |
| UE→AMF | PDUSessionAuthenticationComplete | TS 24.501 §8.3.5 |
| AMF→UE | PDUSessionAuthenticationResult | TS 24.501 §8.3.6 |
| AMF→UE | NetworkSliceSpecificAuthenticationCommand | TS 24.501 §8.2.31 |
| UE→AMF | NetworkSliceSpecificAuthenticationComplete | TS 24.501 §8.2.32 |
| AMF→UE | NetworkSliceSpecificAuthenticationResult | TS 24.501 §8.2.33 |
| AMF→UE | ServiceLevelAuthenticationCommand | TS 24.501 §8.3.17 |
| UE→AMF | ServiceLevelAuthenticationComplete | TS 24.501 §8.3.18 |
| UE→AMF | RelayKeyRequest | TS 24.501 §8.2.34 |
| AMF→UE | RelayKeyAccept / Reject | TS 24.501 §8.2.35-36 |
| AMF→UE | RelayAuthenticationRequest | TS 24.501 §8.2.37 |
| UE→AMF | RelayAuthenticationResponse | TS 24.501 §8.2.38 |
| UE→AMF | RemoteUEReport | TS 24.501 §8.3.19 |
| AMF→UE | RemoteUEReportResponse | TS 24.501 §8.3.20 |

## Phase 15: Raw Endpoint

| Endpoint | Purpose |
|----------|---------|
| POST /ngap | Raw hex in/out — send arbitrary NGAP PDU bytes, receive raw response. Best-effort decode. |
