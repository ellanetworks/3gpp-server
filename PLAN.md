# 3gpp-server-tester Implementation Plan

## Overview

A standalone Go HTTP server that translates JSON to/from NGAP/NAS 3GPP messages over SCTP, with crypto utilities. Ported from the existing tester code at `/home/guillaume/code/core2/internal/tester/` (~17k lines, 127 files, zero Ella Core internal dependencies).

The key architectural change from the existing tester: the old code auto-handles responses (gNB receives message -> auto-dispatches to UE -> UE auto-responds). The new tester breaks that automation. Each message is returned to the HTTP caller as JSON, and the caller (an AI agent) decides what to send next.

## Source Code Reference

All porting is from `/home/guillaume/code/core2/internal/tester/`. Key files:

- `gnb/server.go` — gNB struct, SCTP dial/read/write, state management
- `gnb/handlers.go` — NGAP message dispatcher
- `gnb/send.go` — SCTP send with stream selection
- `gnb/helpers.go` — PLMN/TAC/NRCellIdentity encoding utilities
- `gnb/build_*.go` (9 files) — NGAP message builders
- `gnb/handle_*.go` (8 files) — NGAP message handlers (decode + auto-respond)
- `ue/ue.go` — UE state machine, security context, SUCI encoding, key derivation
- `ue/auth.go` — NAS key derivation (AlgorithmKeyDerivation)
- `ue/nas_encode.go` — NAS encode with security (integrity + ciphering)
- `ue/nas_decode.go` — NAS decode with security unwrap
- `ue/build_*.go` (10 files) — NAS message builders
- `ue/handle_*.go` (11 files) — NAS message handlers (decode + auto-respond)
- `ue/sidf/suci_concealment.go` — SUCI encryption (X25519 + AES)
- `gnb/msg_name.go`, `gnb/cause.go` — enum helpers

External dependencies (from core2/go.mod):
- `github.com/free5gc/aper` v1.1.1 — ASN.1 PER encoding
- `github.com/free5gc/nas` v1.2.3 — NAS message types + security
- `github.com/free5gc/ngap` v1.1.3 — NGAP message types + encode/decode
- `github.com/free5gc/util` v1.3.2 — Milenage, 5G-AKA, KDF
- `github.com/ishidawataru/sctp` — SCTP sockets

## API Design

### gNB Lifecycle

```
POST   /gnb           Create gNB, dial SCTP to AMF, send NGSetupRequest, return response
GET    /gnb/{gnb_id}  Read gNB state
DELETE /gnb/{gnb_id}  Tear down gNB, close SCTP
```

### UE Lifecycle

```
POST   /gnb/{gnb_id}/ue            Create UE context (SUPI, K, OPc), compute SUCI, return ue_id
GET    /gnb/{gnb_id}/ue/{ue_id}    Read full UE state (keys, IDs, SQN, GUTI, counts, ...)
PATCH  /gnb/{gnb_id}/ue/{ue_id}    Override any UE state field (for fuzzing)
DELETE /gnb/{gnb_id}/ue/{ue_id}    Tear down UE
```

### Message Sending

```
POST /gnb/{gnb_id}/ue/{ue_id}/ngap   Send NGAP message using managed state, auto-update on response
POST /ngap                            Raw stateless send (no state tracking)
```

### Crypto

```
POST /crypto/compute-res-star     5G-AKA RES* computation + key derivation
POST /crypto/derive-kamf          K_AMF derivation from CK'/IK'
POST /crypto/derive-nas-keys      K_NASint / K_NASenc from K_AMF
POST /crypto/nas-mac              NAS message authentication code
POST /crypto/nas-cipher           NAS ciphering apply/remove
```

## 3GPP Spec Cross-Reference Process

Every NGAP and NAS message implementation MUST be cross-referenced against the 3GPP specs to ensure all IEs are exposed. The process:

1. **Look up the IE table** in the relevant 3GPP spec:
   - NGAP messages: TS 38.413 §9.2.x (message definitions with IE tables)
   - NAS messages: TS 24.501 §8.2.x (message definitions with IE tables)
   - Security: TS 33.501
   - Procedures: TS 23.502

2. **Cross-reference against free5gc types** in `ngapType/ProtocolIEField.go` (NGAP) or `nasType/` + `nasMessage/` (NAS). The `*IEsValue` structs list every IE the library can encode/decode, with `referenceFieldValue` APER tags mapping to IE IDs.

3. **Verify all IEs are implemented** — both mandatory (M) and optional (O) IEs must be supported in encode and decode. Optional IEs are omitted when nil/absent in JSON, but the code path must exist.

4. **Use the 3GPP MCP tool** (`mcp__3gpp__*`) to look up IE tables, procedure descriptions, and cause code definitions when implementing each message type.

### Verified IE Tables

#### NGSetupRequest (TS 38.413 §9.2.6.1)
| IE | IE ID | Presence | Criticality | JSON field |
|---|---|---|---|---|
| Global RAN Node ID | 27 | M | reject | `global_ran_node_id` |
| RAN Node Name | 82 | O | ignore | `ran_node_name` |
| Supported TA List | 102 | M | reject | `supported_ta_list` |
| Default Paging DRX | 21 | M | ignore | `default_paging_drx` |
| UE Retention Information | 147 | O | ignore | `ue_retention_information` |

#### NGSetupResponse (TS 38.413 §9.2.6.2)
| IE | IE ID | Presence | Criticality | JSON field |
|---|---|---|---|---|
| AMF Name | 1 | M | reject | `amf_name` |
| Served GUAMI List | 96 | M | reject | `served_guami_list` |
| Relative AMF Capacity | 86 | M | ignore | `relative_amf_capacity` |
| PLMN Support List | 80 | M | reject | `plmn_support_list` |
| Criticality Diagnostics | 19 | O | ignore | `criticality_diagnostics` |
| UE Retention Information | 147 | O | ignore | `ue_retention_information` |

#### NGSetupFailure (TS 38.413 §9.2.6.3)
| IE | IE ID | Presence | Criticality | JSON field |
|---|---|---|---|---|
| Cause | 15 | M | ignore | `cause` |
| Time To Wait | 107 | O | ignore | `time_to_wait` |
| Criticality Diagnostics | 19 | O | ignore | `criticality_diagnostics` |

## JSON Schema Design — IE-Level Fidelity

The JSON schema mirrors NGAP IEs and NAS IEs 1:1 to allow complex fuzzing (omitting mandatory IEs, reordering, duplicating, setting wrong criticality values, etc.).

### NGAP Messages

JSON is an ordered list of IEs matching `ProtocolIEs.List`:

```json
{
  "procedure_code": 15,
  "pdu_type": "initiating_message",
  "criticality": "ignore",
  "ies": [
    {
      "id": 85,
      "criticality": "reject",
      "ran_ue_ngap_id": 1
    },
    {
      "id": 38,
      "criticality": "reject",
      "nas_pdu": "7e004171..."
    },
    {
      "id": 121,
      "criticality": "reject",
      "user_location_information": {
        "present": "nr",
        "nr": {
          "nr_cgi": {
            "plmn_identity": "00f110",
            "nr_cell_identity": "0000000001"
          },
          "tai": {
            "plmn_identity": "00f110",
            "tac": "000001"
          }
        }
      }
    },
    {
      "id": 90,
      "criticality": "ignore",
      "rrc_establishment_cause": 3
    }
  ]
}
```

The tester encodes exactly what it receives. No validation guards ("MCC is required" etc. are stripped). Agent controls which IEs are present, their order, criticality, and values.

### NAS Messages

JSON mirrors free5gc `nasMessage.*` struct fields, all optional:

```json
{
  "message_type": "registration_request",
  "extended_protocol_discriminator": 126,
  "security_header_type": 0,
  "registration_type": 1,
  "ngksi": {"tsc": 0, "ksi": 7},
  "mobile_identity": "suci-0-001-01-0000-0-0-0000000001",
  "ue_security_capability": "e0e0",
  "requested_nssai": {
    "snssais": [{"sst": 1, "sd": "010203"}]
  },
  "capability_5gmm": null,
  "uplink_data_status": null,
  "pdu_session_status": null,
  "nas_message_container": null
}
```

Present fields get encoded. Null or absent fields are omitted from the NAS PDU.

### Raw Bytes Escape Hatch

Both levels support a `raw_pdu` / `raw_nas` hex field that bypasses encoding entirely, for sending truly arbitrary bytes.

### Responses

Responses decode to the same IE-level JSON structure, so the agent sees exactly which IEs came back, in what order, with what values.

### Stateful Endpoint Behavior

`POST /gnb/{gnb_id}/ue/{ue_id}/ngap`:
- If `ies` is omitted, auto-constructs the default IE list for that procedure from stored gNB/UE state
- If `ies` is provided, encodes exactly what's given
- Partial list + `"auto_fill": true` merges provided IEs with defaults (provided values win)
- Auto-updates UE state from AMF responses (AMF UE NGAP ID, security algorithms, GUTI, etc.)
- Does NOT auto-respond — returns decoded message to caller

## Directory Structure

```
3gpp-server/
  cmd/3gpp-server-tester/
    main.go                       HTTP server entrypoint
  internal/
    api/
      router.go                   Go 1.22+ net/http mux, route registration
      gnb_handlers.go             POST/GET/DELETE /gnb
      ue_handlers.go              POST/GET/PATCH/DELETE /gnb/{gnb_id}/ue/{ue_id}
      ngap_handlers.go            POST /gnb/{id}/ue/{id}/ngap, POST /ngap
      crypto_handlers.go          POST /crypto/*
      types.go                    JSON request/response structs
      errors.go                   Error response helpers
    store/
      store.go                    Thread-safe in-memory store for gNBs and UEs
      gnb_context.go              gNB context struct and operations
      ue_context.go               UE context struct (security state, IDs, keys)
    transport/
      sctp.go                     SCTP dial, send, receive (from gnb/server.go)
      receiver.go                 Background SCTP reader, pushes frames to channel
    ngap/
      encode.go                   JSON -> NGAP PDU (all builder functions)
      decode.go                   NGAP PDU -> JSON (all handler/parser functions)
      types.go                    JSON schema types for all NGAP IEs
      helpers.go                  PLMN/TAC/NRCellIdentity encoding (from gnb/helpers.go)
    nas/
      encode.go                   JSON -> NAS PDU (all NAS builders)
      decode.go                   NAS PDU -> JSON (NAS message type dispatch + field extraction)
      security.go                 NAS encode/decode with security (from ue/nas_encode.go, nas_decode.go)
      types.go                    JSON schema types for all NAS IEs
    crypto/
      aka.go                      RES*, Kamf, Kausf, Kseaf derivation (from ue/ue.go DeriveRESstarAndSetKey)
      keys.go                     NAS key derivation (from ue/auth.go AlgorithmKeyDerivation)
      mac.go                      NAS MAC compute (wraps security.NASMacCalculate)
      cipher.go                   NAS encrypt/decrypt (wraps security.NASEncrypt)
      suci.go                     SUCI concealment (from ue/sidf/)
  api/
    openapi.yaml                  Hand-written OpenAPI spec (the contract the Python agent consumes)
  go.mod
  go.sum
```

## Build Order

### Phase 1: Skeleton + SCTP + NGSetup

First thing that talks to a real AMF.

| Step | File | Source | Action |
|------|------|--------|--------|
| 1 | `go.mod` | fresh | Dependencies: free5gc/nas, ngap, aper, util; ishidawataru/sctp |
| 2 | `cmd/3gpp-server-tester/main.go` | fresh | HTTP server, `--listen` and `--log-level` flags |
| 3 | `internal/store/store.go` | fresh | Thread-safe `map[string]*GnBContext`, CRUD methods |
| 4 | `internal/store/gnb_context.go` | adapt `gnb/server.go` | Keep: MCC/MNC/TAC/GnbID/SST/SD/Name, UE pool, NGAP ID map. Remove: multi-peer failover, GTP, TUN, Wait* methods |
| 5 | `internal/transport/sctp.go` | adapt `gnb/server.go` lines 416-520 + `gnb/send.go` | Dial(), Send(), Receive(), Close(). Single peer, no rotation. Receiver goroutine pushes frames onto channel |
| 6 | `internal/ngap/helpers.go` | port `gnb/helpers.go` verbatim | GetMccAndMncInOctets, GetTacInBytes, GetPLMNIdentity, GetNRCellIdentity |
| 7 | `internal/ngap/encode.go` | port `gnb/build_ng_setup_request.go` | BuildNGSetupRequest only, adapted for IE-level JSON input |
| 8 | `internal/ngap/decode.go` | port from `gnb/handle_ng_setup_response.go` + `handle_ng_setup_failure.go` | Decode NGAP PDU, extract IEs into JSON struct |
| 9 | `internal/api/router.go` | fresh | Go 1.22+ net/http mux |
| 10 | `internal/api/gnb_handlers.go` | fresh | POST /gnb (dial SCTP, send NGSetup, return response), GET/DELETE /gnb |

**Milestone**: `curl -X POST localhost:8080/gnb -d '{"amf_address":"10.0.0.1:38412", ...}'` returns NGSetupResponse JSON.

**Status**: COMPLETE. Validated against ghcr.io/ellanetworks/ella-core:v1.11.0. All IEs cross-referenced against TS 38.413 §9.2.6.1-3.

### Phase 2: UE Context + First NAS Message

**3GPP cross-reference required before implementation:**
- InitialUEMessage: TS 38.413 §9.2.5.1 — look up all IEs (RAN-UE-NGAP-ID, NAS-PDU, UserLocationInformation, RRCEstablishmentCause, FiveG-S-TMSI, AMFSetID, UEContextRequest, AllowedNSSAI, SourceToTargetAMFInformationReroute)
- DownlinkNASTransport: TS 38.413 §9.2.3.1 — look up all IEs
- RegistrationRequest: TS 24.501 §8.2.6 — look up all NAS IEs
- AuthenticationRequest: TS 24.501 §8.2.1 — look up all NAS IEs

| Step | File | Source | Action |
|------|------|--------|--------|
| 1 | `internal/store/ue_context.go` | adapt `ue/ue.go` UE+UESecurity structs | Keep: credentials (K, OPc, SQN), identity (SUPI, MSIN, SUCI), security state, session config. Remove: air interface, Gnb field, Send*/WaitFor* methods, cond/mutex message queues |
| 2 | `internal/crypto/suci.go` | port `ue/sidf/suci_concealment.go` verbatim | SUCI concealment as pure function |
| 3 | `internal/nas/types.go` | fresh | IE-level JSON types for all NAS messages |
| 4 | `internal/nas/encode.go` | port `ue/build_registration_request.go` | Adapt: IE-level JSON input, all fields optional, no validation |
| 5 | `internal/ngap/encode.go` | port `gnb/build_initial_ue_message.go` | Add BuildInitialUEMessage, IE-level JSON, strip validation guards |
| 6 | `internal/ngap/decode.go` | port from `gnb/handle_downlink_nas_transport.go` | Extract AMF UE NGAP ID + RAN UE NGAP ID + NAS PDU |
| 7 | `internal/nas/decode.go` | port NAS message type dispatch from `ue/ue.go` SendDownlinkNAS | Identify NAS message type, extract fields into IE-level JSON |
| 8 | `internal/api/ue_handlers.go` | fresh | POST/GET/PATCH/DELETE for /gnb/{id}/ue/{id} |
| 9 | `internal/api/ngap_handlers.go` | fresh | POST /gnb/{id}/ue/{id}/ngap — build NAS, wrap in NGAP, send, receive, decode, auto-update state, do NOT auto-respond, return JSON |

**Milestone**: Create gNB, create UE, send registration_request -> get back AuthenticationRequest JSON with RAND and AUTN.

### Phase 3: Crypto + Full Authentication Flow

| Step | File | Source | Action |
|------|------|--------|--------|
| 1 | `internal/crypto/aka.go` | port `ue/ue.go` lines 350-440 | ComputeResStar(k, opc, sqn, rand, autn, snn) -> res_star, kamf, ck, ik. Pure function |
| 2 | `internal/crypto/keys.go` | port `ue/auth.go` | DeriveNASKeys(kamf, cipherAlg, integrityAlg) -> knas_enc, knas_int |
| 3 | `internal/crypto/mac.go` | wrap security.NASMacCalculate | Pure function |
| 4 | `internal/crypto/cipher.go` | wrap security.NASEncrypt | Pure function |
| 5 | `internal/nas/security.go` | port `ue/nas_encode.go` + `ue/nas_decode.go` | NAS encode with integrity+ciphering, decode with security unwrap |
| 6 | `internal/nas/encode.go` | port `ue/build_registration_response.go` + `build_security_mode_complete.go` + `build_registration_complete.go` | AuthenticationResponse, SecurityModeComplete, RegistrationComplete |
| 7 | `internal/nas/decode.go` | port field extraction from `ue/handle_security_mode_command.go` + `ue/handle_registration_accept.go` | Extract: algorithms, GUTI, TAI list, allowed NSSAI |
| 8 | `internal/ngap/decode.go` | port from `gnb/handle_initial_context_setup_request.go` | Extract: PDU session list, UE AMBR, NAS PDU |
| 9 | `internal/ngap/encode.go` | port `gnb/build_initial_context_setup_response.go` | BuildInitialContextSetupResponse |
| 10 | `internal/api/crypto_handlers.go` | fresh | All 5 crypto endpoints |

**Milestone**: Full registration via curl: RegistrationRequest -> AuthenticationRequest -> /crypto/compute-res-star -> AuthenticationResponse -> SecurityModeCommand -> SecurityModeComplete -> RegistrationAccept.

**3GPP cross-reference required before implementation:**
- InitialContextSetupRequest: TS 38.413 §9.2.2.1
- InitialContextSetupResponse: TS 38.413 §9.2.2.2
- SecurityModeCommand: TS 24.501 §8.2.25
- SecurityModeComplete: TS 24.501 §8.2.26
- AuthenticationRequest: TS 24.501 §8.2.1
- AuthenticationResponse: TS 24.501 §8.2.2
- RegistrationAccept: TS 24.501 §8.2.7
- RegistrationComplete: TS 24.501 §8.2.8
- 5G-AKA: TS 33.501 §6.1.3

### Phase 4: PDU Session + Deregistration

| Step | File | Source | Action |
|------|------|--------|--------|
| 1 | `internal/nas/encode.go` | port `ue/build_pdu_session_establishment_request.go` + `ue/build_uplink_nas_transport.go` | PDUSessionEstablishmentRequest in ULNASTransport |
| 2 | `internal/ngap/encode.go` | port `gnb/build_uplink_nas_transport.go` + `gnb/build_pdu_session_resource_setup_response.go` | UplinkNASTransport, PDUSessionResourceSetupResponse |
| 3 | `internal/ngap/decode.go` | port from `gnb/handle_pdu_session_resource_setup_request.go` | Extract GTP TEID, transport address, NAS PDU |
| 4 | `internal/nas/decode.go` | port from `ue/handle_pdu_session_establishment_accept.go` | Extract UE IP, QoS rules, MTU |
| 5 | `internal/nas/encode.go` | port `ue/build_deregistration_request.go` | DeregistrationRequest builder |
| 6 | `internal/ngap/encode.go` | port `gnb/build_ue_context_release_complete.go` | UEContextReleaseComplete |
| 7 | `internal/ngap/decode.go` | port from `gnb/handle_ue_context_release_command.go` | Decode UEContextReleaseCommand |

**Milestone**: Full happy path — registration + PDU session + deregistration, all agent-driven.

**3GPP cross-reference required before implementation:**
- UplinkNASTransport: TS 38.413 §9.2.3.2
- PDUSessionResourceSetupRequest: TS 38.413 §9.2.1.1
- PDUSessionResourceSetupResponse: TS 38.413 §9.2.1.2
- UEContextReleaseCommand: TS 38.413 §9.2.2.5
- UEContextReleaseComplete: TS 38.413 §9.2.2.6
- PDUSessionEstablishmentRequest: TS 24.501 §8.3.1
- PDUSessionEstablishmentAccept: TS 24.501 §8.3.2
- DeregistrationRequest (UE-initiated): TS 24.501 §8.2.11

### Phase 5: Remaining Messages

| Step | File | Source | Action |
|------|------|--------|--------|
| 1 | `internal/nas/encode.go` | port remaining `ue/build_*.go` | IdentityResponse, ServiceRequest, ConfigurationUpdateComplete |
| 2 | `internal/nas/decode.go` | port remaining `ue/handle_*.go` | IdentityRequest, ServiceAccept, ConfigurationUpdateCommand, AuthenticationReject, RegistrationReject, DeregistrationRequest (network-initiated) |
| 3 | `internal/ngap/encode.go` | port remaining `gnb/build_*.go` | UEContextReleaseRequest, NGReset, PathSwitchRequest |
| 4 | `internal/ngap/decode.go` | port remaining `gnb/handle_*.go` | Paging, ErrorIndication, NGResetAcknowledge |

**Milestone**: Every NAS/NGAP message the existing tester supports is available via HTTP.

**3GPP cross-reference required before implementation:**
- All remaining NGAP messages: TS 38.413 §9.2.x
- All remaining NAS messages: TS 24.501 §8.2.x and §8.3.x
- IdentityRequest/Response: TS 24.501 §8.2.21/22
- ServiceRequest/Accept: TS 24.501 §8.2.15/16
- Paging: TS 38.413 §9.2.4.1
- ErrorIndication: TS 38.413 §9.2.7.1

### Phase 6: Raw Endpoint + OpenAPI Spec

| Step | File | Source | Action |
|------|------|--------|--------|
| 1 | `internal/api/ngap_handlers.go` | fresh | POST /ngap — raw hex in/out, optional best-effort decode |
| 2 | `api/openapi.yaml` | fresh | Hand-written, all endpoints, all IE-level JSON schemas |
| 3 | Integration tests | fresh | Against real Ella Core — NGSetup, registration, PDU session, deregistration |

## What Gets Ported vs Written Fresh vs Skipped

### Port verbatim
- `gnb/helpers.go` — pure PLMN/TAC/NRCellIdentity utilities
- `gnb/msg_name.go` — message name lookup
- `gnb/cause.go` — cause code helpers
- `ue/auth.go` — AlgorithmKeyDerivation, SelectAlgorithms
- `ue/sidf/suci_concealment.go` — SUCI crypto

### Port with adaptation
- `gnb/server.go` — keep SCTP dial/read/write, remove multi-peer failover, GTP, TUN
- `gnb/build_*.go` (9 files) — adapt input from Opts structs to IE-level JSON, strip validation guards
- `gnb/handle_*.go` (8 files) — keep IE extraction/decode, remove auto-response sending
- `ue/ue.go` — keep UESecurity struct fields for UEContext, keep DeriveRESstarAndSetKey/DerivateKamf as pure functions. Remove: air interface, Gnb field, Send*/WaitFor*, message queues
- `ue/build_*.go` (10 files) — adapt input to IE-level JSON, all IEs optional
- `ue/handle_*.go` (11 files) — keep field extraction, remove auto-response
- `ue/nas_encode.go` — keep NAS security encode, operate on UEContext
- `ue/nas_decode.go` — keep NAS security decode, operate on UEContext
- `gnb/send.go` — keep writeToConn + SCTP stream selection, remove Send* convenience methods

### Write fresh
- `cmd/3gpp-server-tester/main.go` — HTTP server
- `internal/api/*` — all HTTP handlers
- `internal/store/*` — state management
- `internal/ngap/types.go` — IE-level JSON schema types
- `internal/nas/types.go` — IE-level JSON schema types
- `api/openapi.yaml` — OpenAPI spec

### Skip entirely
- `gnb/gtp.go` — user-plane, not needed for signaling testing
- `gnb/server.go` multi-peer failover — HA feature, tester connects to one AMF
- `ue/ue.go` WaitFor*/cond/message queues — replaced by sync HTTP request-response
- `air/air.go` — interface for auto-dispatch, not needed
- `scenarios/**` (50 files) — replaced by the Python agent
- `testutil/procedure/**` — orchestration logic moves to agent
- `testutil/validate/**` — validation logic moves to agent
- `enb/**` — 4G not in scope
- `logger/logger.go` — write fresh (simpler, for HTTP server)
