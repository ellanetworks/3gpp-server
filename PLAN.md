# 3gpp-server Implementation Plan

## Overview

A standalone Go HTTP server that translates JSON to/from NGAP/NAS 3GPP messages over SCTP, with crypto utilities. Designed to be driven by an AI agent for conformance testing, fuzzing, and security assessment of 5G core networks.

The JSON schema mirrors NGAP/NAS IEs 1:1 so the caller controls which IEs are present, their order, criticality, and values — enabling both correct procedures and deliberate deviations. Every message type supports a `raw_nas_pdu` escape hatch for sending arbitrary bytes.

## Source Code Reference

Porting from `/home/guillaume/code/core2/internal/tester/` (~17k lines, 127 files, zero Ella Core internal dependencies).

## 3GPP Spec Cross-Reference

Every message implementation must be cross-referenced against the 3GPP spec PDFs in the repo root and free5gc types:

1. Look up the IE table in TS 38.413 §9.2.x (NGAP) or TS 24.501 §8.x (NAS)
2. Cross-reference against free5gc `*IEsValue` structs
3. Verify all IEs (mandatory and optional) have encode and decode paths

## Completed

- **Phase 1:** gNB lifecycle (NGSetupRequest/Response/Failure)
- **Phase 2:** UE lifecycle + InitialUEMessage + DownlinkNASTransport + RegistrationRequest + AuthenticationRequest decode
- **Phase 3:** Full authentication flow (5G-AKA, NAS security, AuthenticationResponse, SecurityModeCommand/Complete, RegistrationAccept/Complete, InitialContextSetupRequest/Response)

89 integration tests. Full registration via the API validated against Ella Core.

## Phase 4: PDU Session Establishment

| Direction | NGAP Message | NAS Message | Spec Reference |
|-----------|-------------|-------------|----------------|
| UE→AMF | UplinkNASTransport | PDUSessionEstablishmentRequest | TS 24.501 §8.3.1 |
| AMF→gNB | PDUSessionResourceSetupRequest | PDUSessionEstablishmentAccept | TS 38.413 §9.2.1.1, TS 24.501 §8.3.2 |
| gNB→AMF | PDUSessionResourceSetupResponse | — | TS 38.413 §9.2.1.2 |

**Milestone**: Registration + PDU session establishment.

## Phase 5: Deregistration

| Direction | NGAP Message | NAS Message | Spec Reference |
|-----------|-------------|-------------|----------------|
| UE→AMF | UplinkNASTransport | DeregistrationRequest (UE-originated) | TS 24.501 §8.2.11 |
| AMF→UE | DownlinkNASTransport | DeregistrationAccept | TS 24.501 §8.2.12 |
| AMF→gNB | UEContextReleaseCommand | — | TS 38.413 §9.2.2.5 |
| gNB→AMF | UEContextReleaseComplete | — | TS 38.413 §9.2.2.6 |

**Milestone**: Full happy path — registration + PDU session + deregistration.

## Phase 6: Service Request + Paging

| Direction | NGAP Message | NAS Message | Spec Reference |
|-----------|-------------|-------------|----------------|
| UE→AMF | InitialUEMessage | ServiceRequest | TS 24.501 §8.2.15 |
| AMF→UE | DownlinkNASTransport | ServiceAccept / ServiceReject | TS 24.501 §8.2.16-17 |
| AMF→gNB | Paging | — | TS 38.413 §9.2.4.1 |

**Milestone**: Idle-mode UE can be paged and resume connectivity.

## Phase 7: Identity + Configuration

| Direction | NGAP Message | NAS Message | Spec Reference |
|-----------|-------------|-------------|----------------|
| AMF→UE | DownlinkNASTransport | IdentityRequest | TS 24.501 §8.2.21 |
| UE→AMF | UplinkNASTransport | IdentityResponse | TS 24.501 §8.2.22 |
| AMF→UE | DownlinkNASTransport | ConfigurationUpdateCommand | TS 24.501 §8.2.19 |
| UE→AMF | UplinkNASTransport | ConfigurationUpdateComplete | TS 24.501 §8.2.20 |
| AMF→UE | DownlinkNASTransport | DeregistrationRequest (network-initiated) | TS 24.501 §8.2.13 |

**Milestone**: All NAS messages the Ella Core tester supports.

## Phase 8: NGAP Management + Error Handling

| Direction | NGAP Message | Spec Reference |
|-----------|-------------|----------------|
| gNB→AMF | NGReset | TS 38.413 §9.2.6.4 |
| AMF→gNB | NGResetAcknowledge | TS 38.413 §9.2.6.5 |
| both | ErrorIndication | TS 38.413 §9.2.7.1 |
| gNB→AMF | PathSwitchRequest | TS 38.413 §9.2.3.8 |
| AMF→gNB | PathSwitchRequestAcknowledge/Failure | TS 38.413 §9.2.3.9-10 |
| gNB→AMF | UEContextReleaseRequest | TS 38.413 §9.2.2.4 |

**Milestone**: All NGAP messages the Ella Core tester supports.

## Future: Full TS 38.413 + TS 24.501 Coverage

The phases above cover the messages implemented in the Ella Core tester. Beyond that, TS 38.413 defines ~60 NGAP procedures and TS 24.501 defines ~40 NAS message types. Coverage will expand incrementally as needed:

- Handover procedures (HandoverRequired/Request/Command/Notify, TS 38.413 §8.4)
- PDU session modification/release (TS 24.501 §8.3.3-8)
- 5GSM status and notification (TS 24.501 §8.3.9-10)
- EAP-based authentication (TS 24.501 §8.2.1-4)
- N2 handover (TS 38.413 §8.4)
- AMF/RAN configuration update (TS 38.413 §9.2.6.7-10)
- RAW endpoint (POST /ngap — raw hex in/out, best-effort decode)
