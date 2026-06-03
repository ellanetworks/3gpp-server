# 3gpp-server

Use 3GPP server to test security, performance, and reliability aspects of 5G cores.

3GPP server exposes an HTTP API that humans and AIs can use to send carefully crafted NGAP and NAS messages to the core.

## Message support

The server emulates a gNB (NGAP peer) and a UE (NAS peer). For each message the
tables below show whether the server can **send** it to the core and whether it
**decodes** a received instance. The tables enumerate the complete message
catalogs of TS 38.413 (NGAP) and TS 24.501 (NAS).

Legend:

- ✅ — implemented (send: built and reachable via the API; decode: message fields extracted into the response)
- 🟡 — partial (decode: message type is recognized and named, but its information elements are not extracted)
- ❌ — not implemented (neither built nor decoded)
- — — not used in this direction by the emulated gNB/UE role

### Limitations

Structured message building uses [`github.com/free5gc/nas`](https://github.com/free5gc/nas)
and `github.com/free5gc/ngap`. Those libraries model a fixed set of IEs, so some
later-3GPP-release information elements (e.g. the RegistrationRequest extended
DRX, T3324, UE radio capability ID, requested mapped NSSAI, WUS assistance,
N5GC indication, NB-N1 mode DRX, UE request type, and paging restriction IEs)
cannot be set through the structured request fields. To send these — or any
fully arbitrary or deliberately malformed message — use the `raw_nas_pdu`
override, which puts caller-supplied bytes directly into the NAS PDU.

At the NGAP layer the equivalent escape hatch is `raw_ngap_pdu` on
`POST /gnb/{gnb_id}/ngap`: caller-supplied bytes are written verbatim onto the
N2 association with no encoding or validation, so a test can craft any NGAP PDU
at all — well-formed, malformed, out-of-sequence, or pure garbage — to probe
how the core reacts (it must respond appropriately and never crash). With
`wait_for` the call returns the resulting downlink message; otherwise it is
fire-and-forget.

We may drop the free5gc dependency in the future and build messages directly,
to allow fully granular control over every IE without these escape hatches.

### NGAP (TS 38.413)

#### Interface management

| Message | Send | Decode |
|---|:---:|:---:|
| NG Setup Request | ✅ | — |
| NG Setup Response | — | ✅ |
| NG Setup Failure | — | ✅ |
| RAN Configuration Update | ❌ | ❌ |
| RAN Configuration Update Acknowledge | ❌ | ❌ |
| RAN Configuration Update Failure | ❌ | ❌ |
| AMF Configuration Update | ❌ | ❌ |
| AMF Configuration Update Acknowledge | ❌ | ❌ |
| AMF Configuration Update Failure | ❌ | ❌ |
| NG Reset | ✅ | 🟡 |
| NG Reset Acknowledge | — | ✅ |
| Overload Start | ❌ | ❌ |
| Overload Stop | ❌ | ❌ |
| Error Indication | ❌ | 🟡 |
| AMF Status Indication | ❌ | ❌ |
| Private Message | ❌ | ❌ |

#### UE context management

| Message | Send | Decode |
|---|:---:|:---:|
| Initial Context Setup Request | — | ✅ |
| Initial Context Setup Response | ✅ | 🟡 |
| Initial Context Setup Failure | ❌ | 🟡 |
| UE Context Release Request | ✅ | — |
| UE Context Release Command | — | ✅ |
| UE Context Release Complete | ✅ | 🟡 |
| UE Context Modification Request | ❌ | ❌ |
| UE Context Modification Response | ❌ | ❌ |
| UE Context Modification Failure | ❌ | ❌ |
| UE Context Resume Request | ❌ | ❌ |
| UE Context Resume Response | ❌ | ❌ |
| UE Context Resume Failure | ❌ | ❌ |
| UE Context Suspend Request | ❌ | ❌ |
| UE Context Suspend Response | ❌ | ❌ |
| UE Context Suspend Failure | ❌ | ❌ |
| Connection Establishment Indication | ❌ | ❌ |
| RRC Inactive Transition Report | ❌ | ❌ |
| RAN CP Relocation Indication | ❌ | ❌ |
| Retrieve UE Information | ❌ | ❌ |
| UE Information Transfer | ❌ | ❌ |

#### PDU session management

| Message | Send | Decode |
|---|:---:|:---:|
| PDU Session Resource Setup Request | — | ✅ |
| PDU Session Resource Setup Response | ✅ | 🟡 |
| PDU Session Resource Modify Request | ❌ | ✅ |
| PDU Session Resource Modify Response | ❌ | ❌ |
| PDU Session Resource Modify Indication | ❌ | ❌ |
| PDU Session Resource Modify Confirm | ❌ | ❌ |
| PDU Session Resource Release Command | — | ✅ |
| PDU Session Resource Release Response | ✅ | — |
| PDU Session Resource Notify | ❌ | ❌ |

#### NAS transport

| Message | Send | Decode |
|---|:---:|:---:|
| Initial UE Message | ✅ | — |
| Downlink NAS Transport | — | ✅ |
| Uplink NAS Transport | ✅ | — |
| NAS Non Delivery Indication | ❌ | ❌ |
| Reroute NAS Request | ❌ | ❌ |

#### Paging

| Message | Send | Decode |
|---|:---:|:---:|
| Paging | — | 🟡 |
| RAN Paging Request | ❌ | ❌ |

#### Mobility and handover

| Message | Send | Decode |
|---|:---:|:---:|
| Handover Required | ✅ | — |
| Handover Command | — | ✅ |
| Handover Preparation Failure | — | ✅ |
| Handover Request | — | ✅ |
| Handover Request Acknowledge | ✅ | — |
| Handover Failure | ✅ | — |
| Handover Notify | ✅ | — |
| Handover Success | ❌ | ❌ |
| Handover Cancel | ✅ | — |
| Handover Cancel Acknowledge | — | ✅ |
| Path Switch Request | ❌ | ❌ |
| Path Switch Request Acknowledge | — | 🟡 |
| Path Switch Request Failure | — | 🟡 |
| Uplink RAN Status Transfer | ❌ | ❌ |
| Downlink RAN Status Transfer | ❌ | ❌ |
| Uplink RAN Early Status Transfer | ❌ | ❌ |
| Downlink RAN Early Status Transfer | ❌ | ❌ |

#### Transport of RAN / NRPPa / RIM information

| Message | Send | Decode |
|---|:---:|:---:|
| Uplink RAN Configuration Transfer | ❌ | ❌ |
| Downlink RAN Configuration Transfer | ❌ | ❌ |
| Uplink UE-Associated NRPPa Transport | ❌ | ❌ |
| Downlink UE-Associated NRPPa Transport | ❌ | ❌ |
| Uplink Non-UE-Associated NRPPa Transport | ❌ | ❌ |
| Downlink Non-UE-Associated NRPPa Transport | ❌ | ❌ |
| Uplink RIM Information Transfer | ❌ | ❌ |
| Downlink RIM Information Transfer | ❌ | ❌ |

#### Warning message transmission (PWS)

| Message | Send | Decode |
|---|:---:|:---:|
| Write-Replace Warning Request | ❌ | ❌ |
| Write-Replace Warning Response | ❌ | ❌ |
| PWS Cancel Request | ❌ | ❌ |
| PWS Cancel Response | ❌ | ❌ |
| PWS Restart Indication | ❌ | ❌ |
| PWS Failure Indication | ❌ | ❌ |

#### Trace and location reporting

| Message | Send | Decode |
|---|:---:|:---:|
| Trace Start | ❌ | ❌ |
| Trace Failure Indication | ❌ | ❌ |
| Deactivate Trace | ❌ | ❌ |
| Cell Traffic Trace | ❌ | ❌ |
| Location Reporting Control | ❌ | ❌ |
| Location Reporting Failure Indication | ❌ | ❌ |
| Location Report | ❌ | ❌ |

#### UE radio capability

| Message | Send | Decode |
|---|:---:|:---:|
| UE Radio Capability Info Indication | ❌ | ❌ |
| UE Radio Capability Check Request | ❌ | ❌ |
| UE Radio Capability Check Response | ❌ | ❌ |
| UE Radio Capability ID Mapping Request | ❌ | ❌ |
| UE Radio Capability ID Mapping Response | ❌ | ❌ |

#### Other

| Message | Send | Decode |
|---|:---:|:---:|
| Secondary RAT Data Usage Report | ❌ | ❌ |
| UE TNLA Binding Release Request | ❌ | ❌ |
| AMF CP Relocation Indication | ❌ | ❌ |
| MT Communication Handling Request | ❌ | ❌ |
| MT Communication Handling Response | ❌ | ❌ |
| MT Communication Handling Failure | ❌ | ❌ |
| Timing Synchronisation Status Request | ❌ | ❌ |
| Timing Synchronisation Status Response | ❌ | ❌ |
| Timing Synchronisation Status Failure | ❌ | ❌ |
| Timing Synchronisation Status Report | ❌ | ❌ |

#### MBS (multicast / broadcast)

| Message | Send | Decode |
|---|:---:|:---:|
| Broadcast Session Setup Request | ❌ | ❌ |
| Broadcast Session Setup Response | ❌ | ❌ |
| Broadcast Session Setup Failure | ❌ | ❌ |
| Broadcast Session Modification Request | ❌ | ❌ |
| Broadcast Session Modification Response | ❌ | ❌ |
| Broadcast Session Modification Failure | ❌ | ❌ |
| Broadcast Session Release Request | ❌ | ❌ |
| Broadcast Session Release Response | ❌ | ❌ |
| Broadcast Session Release Required | ❌ | ❌ |
| Broadcast Session Transport Request | ❌ | ❌ |
| Broadcast Session Transport Response | ❌ | ❌ |
| Broadcast Session Transport Failure | ❌ | ❌ |
| Distribution Setup Request | ❌ | ❌ |
| Distribution Setup Response | ❌ | ❌ |
| Distribution Setup Failure | ❌ | ❌ |
| Distribution Release Request | ❌ | ❌ |
| Distribution Release Response | ❌ | ❌ |
| Multicast Session Activation Request | ❌ | ❌ |
| Multicast Session Activation Response | ❌ | ❌ |
| Multicast Session Activation Failure | ❌ | ❌ |
| Multicast Session Deactivation Request | ❌ | ❌ |
| Multicast Session Deactivation Response | ❌ | ❌ |
| Multicast Session Update Request | ❌ | ❌ |
| Multicast Session Update Response | ❌ | ❌ |
| Multicast Session Update Failure | ❌ | ❌ |
| Multicast Group Paging | ❌ | ❌ |

### NAS — 5GMM (TS 24.501 §8.2 / Table 9.7.1)

| Message | Send | Decode |
|---|:---:|:---:|
| Registration Request | ✅ | 🟡 |
| Registration Accept | — | ✅ |
| Registration Complete | ✅ | 🟡 |
| Registration Reject | — | ✅ |
| Deregistration Request (UE originating) | ✅ | 🟡 |
| Deregistration Accept (UE originating) | — | 🟡 |
| Deregistration Request (UE terminated) | ❌ | 🟡 |
| Deregistration Accept (UE terminated) | ❌ | 🟡 |
| Service Request | ✅ | 🟡 |
| Service Accept | — | 🟡 |
| Service Reject | — | 🟡 |
| Control Plane Service Request | ❌ | ❌ |
| Network Slice-Specific Authentication Command | ❌ | ❌ |
| Network Slice-Specific Authentication Complete | ❌ | ❌ |
| Network Slice-Specific Authentication Result | ❌ | ❌ |
| Configuration Update Command | — | 🟡 |
| Configuration Update Complete | ❌ | 🟡 |
| Authentication Request | — | ✅ |
| Authentication Response | ✅ | 🟡 |
| Authentication Reject | — | 🟡 |
| Authentication Failure | ✅ | — |
| Authentication Result | — | 🟡 |
| Identity Request | — | ✅ |
| Identity Response | ✅ | 🟡 |
| Security Mode Command | — | ✅ |
| Security Mode Complete | ✅ | 🟡 |
| Security Mode Reject | ✅ | 🟡 |
| 5GMM Status | ❌ | ✅ |
| Notification | — | ❌ |
| Notification Response | ❌ | ❌ |
| UL NAS Transport | ✅ | 🟡 |
| DL NAS Transport | — | ✅ |
| Relay Key Request | ❌ | ❌ |
| Relay Key Accept | ❌ | ❌ |
| Relay Key Reject | ❌ | ❌ |
| Relay Authentication Request | ❌ | ❌ |
| Relay Authentication Response | ❌ | ❌ |

### NAS — 5GSM (TS 24.501 §8.3 / Table 9.7.2)

| Message | Send | Decode |
|---|:---:|:---:|
| PDU Session Establishment Request | ✅ | 🟡 |
| PDU Session Establishment Accept | — | ✅ |
| PDU Session Establishment Reject | — | ✅ |
| PDU Session Authentication Command | — | ❌ |
| PDU Session Authentication Complete | ❌ | ❌ |
| PDU Session Authentication Result | — | ❌ |
| PDU Session Modification Request | ❌ | 🟡 |
| PDU Session Modification Reject | — | 🟡 |
| PDU Session Modification Command | — | 🟡 |
| PDU Session Modification Complete | ❌ | ❌ |
| PDU Session Modification Command Reject | ❌ | ❌ |
| PDU Session Release Request | ✅ | 🟡 |
| PDU Session Release Reject | — | 🟡 |
| PDU Session Release Command | — | ✅ |
| PDU Session Release Complete | ✅ | 🟡 |
| 5GSM Status | ❌ | ❌ |
| Service-Level Authentication Command | — | ❌ |
| Service-Level Authentication Complete | ❌ | ❌ |
| Remote UE Report | ❌ | ❌ |
| Remote UE Report Response | — | ❌ |
