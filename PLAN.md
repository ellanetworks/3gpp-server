# 3gpp-server Implementation Plan

## Overview

A standalone Go HTTP server that translates JSON to/from NGAP/NAS 3GPP messages over SCTP, with crypto utilities. Designed to be driven by an AI agent for conformance testing, fuzzing, and security assessment of 5G core networks.

The JSON schema mirrors NGAP/NAS IEs 1:1 so the caller controls which IEs are present, their order, criticality, and values — enabling both correct procedures and deliberate deviations.

## Source Code Reference

Porting from `/home/guillaume/code/core2/internal/tester/` (~17k lines, 127 files, zero Ella Core internal dependencies).

External dependencies:
- `github.com/free5gc/aper` v1.1.1 — ASN.1 PER encoding
- `github.com/free5gc/ngap` v1.1.3 — NGAP message types + encode/decode
- `github.com/free5gc/openapi` v1.2.4 — PLMN conversion helpers
- `github.com/free5gc/nas` v1.2.3 — NAS message types + security (Phase 2+)
- `github.com/free5gc/util` v1.3.2 — Milenage, 5G-AKA, KDF (Phase 3+)
- `github.com/ishidawataru/sctp` — SCTP sockets

## API

### gNB Lifecycle

```
POST   /gnb           Create gNB, dial SCTP to AMF, send NGSetupRequest, return response
GET    /gnb/{gnb_id}  Read gNB state
DELETE /gnb/{gnb_id}  Tear down gNB, close SCTP
```

### UE Lifecycle (Phase 2)

```
POST   /gnb/{gnb_id}/ue            Create UE context (SUPI, K, OPc), compute SUCI, return ue_id
GET    /gnb/{gnb_id}/ue/{ue_id}    Read full UE state (keys, IDs, SQN, GUTI, counts, ...)
PATCH  /gnb/{gnb_id}/ue/{ue_id}    Override any UE state field (for fuzzing)
DELETE /gnb/{gnb_id}/ue/{ue_id}    Tear down UE
```

### Message Sending (Phase 2)

```
POST /gnb/{gnb_id}/ue/{ue_id}/ngap   Send NGAP message using managed state, auto-update on response
POST /ngap                            Raw stateless send (Phase 6)
```

### Crypto (Phase 3)

```
POST /crypto/compute-res-star     5G-AKA RES* computation + key derivation
POST /crypto/derive-kamf          K_AMF derivation from CK'/IK'
POST /crypto/derive-nas-keys      K_NASint / K_NASenc from K_AMF
POST /crypto/nas-mac              NAS message authentication code
POST /crypto/nas-cipher           NAS ciphering apply/remove
```

## 3GPP Spec Cross-Reference

Every message implementation must be cross-referenced against the 3GPP specs and free5gc types to ensure all IEs are exposed:

1. Look up the IE table in TS 38.413 §9.2.x (NGAP) or TS 24.501 §8.x (NAS)
2. Cross-reference against free5gc `*IEsValue` structs in `ngapType/ProtocolIEField.go`
3. Verify all IEs (mandatory and optional) have encode and decode paths

### Verified: NGSetup (Phase 1)

#### NGSetupRequest (TS 38.413 §9.2.6.1)
| IE | ID | M/O | Criticality | JSON field |
|---|---|---|---|---|
| Global RAN Node ID | 27 | M | reject | `global_ran_node_id` |
| RAN Node Name | 82 | O | ignore | `ran_node_name` |
| Supported TA List | 102 | M | reject | `supported_ta_list` |
| Default Paging DRX | 21 | M | ignore | `default_paging_drx` |
| UE Retention Information | 147 | O | ignore | `ue_retention_information` |

#### NGSetupResponse (TS 38.413 §9.2.6.2)
| IE | ID | M/O | Criticality | JSON field |
|---|---|---|---|---|
| AMF Name | 1 | M | reject | `amf_name` |
| Served GUAMI List | 96 | M | reject | `served_guami_list` |
| Relative AMF Capacity | 86 | M | ignore | `relative_amf_capacity` |
| PLMN Support List | 80 | M | reject | `plmn_support_list` |
| Criticality Diagnostics | 19 | O | ignore | `criticality_diagnostics` |
| UE Retention Information | 147 | O | ignore | `ue_retention_information` |

#### NGSetupFailure (TS 38.413 §9.2.6.3)
| IE | ID | M/O | Criticality | JSON field |
|---|---|---|---|---|
| Cause | 15 | M | ignore | `cause` |
| Time To Wait | 107 | O | ignore | `time_to_wait` |
| Criticality Diagnostics | 19 | O | ignore | `criticality_diagnostics` |

## Current Implementation (Phase 1 — Complete)

```
3gpp-server/
  cmd/3gpp-server/
    main.go                     HTTP server, --listen flag
  internal/
    api/
      router.go                 POST/GET/DELETE /gnb
      gnb_handlers.go           Create gNB (SCTP + NGSetup), Get, Delete
      types.go                  JSON request/response structs
      errors.go                 writeError / writeJSON helpers
    store/
      store.go                  Thread-safe map[string]*GnBContext
      gnb_context.go            gNB state: PLMN, TAC, slices, NGAP IDs, UE pool
      ue_context.go             Placeholder for Phase 2
    transport/
      sctp.go                   Dial, Send, Receive (channel-based), Close
    ngap/
      encode.go                 IE-level JSON -> NGAP PDU (NGSetupRequest)
      decode.go                 NGAP PDU -> IE-level JSON (NGSetupResponse, NGSetupFailure)
      types.go                  IE-level JSON types (NGAPMessage, IE, NGAPResponse, ...)
      helpers.go                PLMN/TAC/NRCellIdentity byte encoding
  integration/
    compose.yaml                Docker Compose for testing against Ella Core image
    compose-local.yaml          Docker Compose for testing against locally-built Ella Core
    Dockerfile.ella-core        Builds image from local binary
    test_ng_setup.sh            25-test battery for NGSetup
```

### State Management

The store holds gNB and UE contexts in memory. Each gNB has an SCTP transport and a UE pool.

The stateful `/gnb/{id}/ue/{id}/ngap` endpoint (Phase 2) will:
1. Read stored state to fill omitted fields (RAN UE NGAP ID, NAS SQN, PLMN)
2. Encode and send over SCTP, increment ULCount if NAS security active
3. Receive AMF response, decode to IE-level JSON
4. Auto-update context (AMF UE NGAP ID, security algorithms, GUTI, DLCount)
5. Return decoded response — does NOT auto-respond

Any field explicitly provided in the request overrides stored state for that single request (for fuzzing). `PATCH` mutates stored state permanently.

## Phase 2: UE Context + First NAS Message

**3GPP cross-reference required:**
- InitialUEMessage: TS 38.413 §9.2.5.1
- DownlinkNASTransport: TS 38.413 §9.2.3.1
- RegistrationRequest: TS 24.501 §8.2.6
- AuthenticationRequest: TS 24.501 §8.2.1

**Files to create/modify:**

| File | Action |
|------|--------|
| `internal/store/ue_context.go` | Full UE state: credentials (K, OPc, SQN), identity (SUPI, SUCI, GUTI), NGAP IDs, security keys, NAS counts, session config |
| `internal/crypto/suci.go` | SUCI concealment (port from `ue/sidf/`) |
| `internal/nas/types.go` | IE-level JSON types for NAS messages |
| `internal/nas/encode.go` | RegistrationRequest builder |
| `internal/nas/decode.go` | NAS message type dispatch, AuthenticationRequest field extraction |
| `internal/ngap/encode.go` | Add InitialUEMessage builder |
| `internal/ngap/decode.go` | Add DownlinkNASTransport decoder |
| `internal/api/ue_handlers.go` | POST/GET/PATCH/DELETE /gnb/{id}/ue/{id} |
| `internal/api/ngap_handlers.go` | POST /gnb/{id}/ue/{id}/ngap |
| `internal/api/router.go` | Add UE and NGAP routes |

**Milestone**: Create gNB, create UE, send RegistrationRequest via InitialUEMessage, get back AuthenticationRequest with RAND and AUTN.

## Phase 3: Crypto + Full Authentication Flow

**3GPP cross-reference required:**
- InitialContextSetupRequest/Response: TS 38.413 §9.2.2.1-2
- SecurityModeCommand/Complete: TS 24.501 §8.2.25-26
- AuthenticationRequest/Response: TS 24.501 §8.2.1-2
- RegistrationAccept/Complete: TS 24.501 §8.2.7-8
- 5G-AKA: TS 33.501 §6.1.3

**Files to create/modify:**

| File | Action |
|------|--------|
| `internal/crypto/aka.go` | ComputeResStar — pure function, port from `ue/ue.go` |
| `internal/crypto/keys.go` | DeriveNASKeys — port from `ue/auth.go` |
| `internal/crypto/mac.go` | NAS MAC — wraps `security.NASMacCalculate` |
| `internal/crypto/cipher.go` | NAS cipher — wraps `security.NASEncrypt` |
| `internal/nas/security.go` | NAS encode/decode with integrity + ciphering |
| `internal/nas/encode.go` | Add AuthenticationResponse, SecurityModeComplete, RegistrationComplete |
| `internal/nas/decode.go` | Add SecurityModeCommand, RegistrationAccept field extraction |
| `internal/ngap/encode.go` | Add InitialContextSetupResponse |
| `internal/ngap/decode.go` | Add InitialContextSetupRequest decoder |
| `internal/api/crypto_handlers.go` | All 5 crypto endpoints |

**Milestone**: Full registration via curl.

## Phase 4: PDU Session + Deregistration

**3GPP cross-reference required:**
- UplinkNASTransport: TS 38.413 §9.2.3.2
- PDUSessionResourceSetup Request/Response: TS 38.413 §9.2.1.1-2
- UEContextRelease Command/Complete: TS 38.413 §9.2.2.5-6
- PDUSessionEstablishment Request/Accept: TS 24.501 §8.3.1-2
- DeregistrationRequest: TS 24.501 §8.2.11

**Milestone**: Full happy path — registration + PDU session + deregistration.

## Phase 5: Remaining Messages

**3GPP cross-reference required:**
- IdentityRequest/Response: TS 24.501 §8.2.21-22
- ServiceRequest/Accept: TS 24.501 §8.2.15-16
- Paging: TS 38.413 §9.2.4.1
- ErrorIndication: TS 38.413 §9.2.7.1

**Milestone**: Every NAS/NGAP message the existing core2 tester supports.

## Phase 6: Raw Endpoint + OpenAPI Spec

| File | Action |
|------|--------|
| `internal/api/ngap_handlers.go` | POST /ngap — raw hex in/out, best-effort decode |
| `api/openapi.yaml` | Hand-written spec for all endpoints |

## What Gets Ported vs Written Fresh vs Skipped

**Port verbatim:** `gnb/helpers.go`, `gnb/msg_name.go`, `gnb/cause.go`, `ue/auth.go`, `ue/sidf/`

**Port with adaptation:** `gnb/server.go` (SCTP only, no failover/GTP), `gnb/build_*.go` (IE-level JSON input), `gnb/handle_*.go` (decode only, no auto-response), `ue/ue.go` (state struct only), `ue/build_*.go` (all IEs optional), `ue/handle_*.go` (field extraction only), `ue/nas_encode.go`, `ue/nas_decode.go`

**Write fresh:** `cmd/3gpp-server/main.go`, `internal/api/*`, `internal/store/*`, `internal/ngap/types.go`, `internal/nas/types.go`, `api/openapi.yaml`

**Skip:** `gnb/gtp.go`, multi-peer failover, WaitFor*/cond queues, `air/air.go`, `scenarios/**`, `testutil/**`, `enb/**`
