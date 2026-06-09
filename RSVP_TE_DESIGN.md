# Design Document: Modular RSVP-TE Daemon

## 1. Introduction
This document outlines the architecture and implementation plan for a modular, platform-independent RSVP-TE signaling daemon. The design focuses on scalability (industrial standards), strict separation between protocol logic (PI) and platform-dependent (PD) code, and integration with FRR for Traffic Engineering Database (TED) and Interface management.

## 2. System Architecture

### 2.1 Component Overview
- **Message Dispatcher:** Manages raw network I/O (Protocol 46) and routes packets to the appropriate state machine.
- **Protocol Engine (PI):** Implements the RSVP-TE state machines (PSB/RSB). This is pure logic.
- **State Database:** High-performance hash tables for Path State Blocks (PSB) and Resv State Blocks (RSB).
- **Platform Adapter (HAL):** An abstract interface for label allocation, data plane programming, and timer management.
- **FRR Interface:** ZAPI client to sync interface states and TED from FRR.

## 3. Data Structures

### 3.1 RSVP Keys
Used for O(1) lookups in the state database.
- **PATH Key:** `{Destination IP, Tunnel ID, Extended Tunnel ID, Source IP, LSP ID}`
- **RESV Key:** `{Destination IP, Tunnel ID, Extended Tunnel ID, Filter Source IP, Filter LSP ID}`

### 3.2 State Blocks
- **PSB (Path State Block):** Stores downstream path state, ERO, and upstream neighbor info.
- **RSB (Resv State Block):** Stores upstream reservation state, labels, and downstream neighbor info.

## 4. Message Dispatcher & I/O

### 4.1 The Socket Loop
The daemon runs an asynchronous event loop (e.g., `libevent`).
1. **Listen:** Open a raw socket for IP Protocol 46 (RSVP).
2. **Read:** Buffer the packet and perform a "Shallow Parse" to extract the Key and Message Type.
3. **Dispatch:** Call the Protocol Engine with the parsed key and raw buffer.

## 5. State Machine Transitions

### 5.1 PATH Message Processing (Downstream)
- **If New:** Create PSB -> Validate ERO -> Determine Next Hop -> Program Ingress (if Head-end) -> Forward PATH.
- **If Refresh:** Reset Cleanup Timer.
- **If Tear:** Delete PSB -> Forward PathTear downstream -> Notify associated RSB.

### 5.2 RESV Message Processing (Upstream)
- **If New:** Create RSB -> Find matching PSB -> Allocate Local Label (via HAL) -> Program Data Plane (Swap/Push via HAL) -> Forward RESV Upstream.
- **If Refresh:** Reset Cleanup Timer.
- **If Tear:** Delete RSB -> Program Data Plane (Delete via HAL) -> Forward ResvTear upstream.

## 6. Platform Abstraction Layer (HAL)
To maintain platform independence, the following APIs must be implemented by the PD layer:
- `hal_label_allocate(session_id)`
- `hal_label_free(label)`
- `hal_mpls_install(in_label, out_label, out_intf, next_hop, action)`
- `hal_timer_start(timer_type, timeout_ms, callback, data)`

## 7. Implementation Roadmap
1. **Phase 1:** Core Data Structures & Header Definitions.
2. **Phase 2:** Message Parser & Socket Listener.
3. **Phase 3:** State Machine Logic (The "Happy Path").
4. **Phase 4:** HAL Integration (Linux Kernel as first PD).
5. **Phase 5:** FRR Integration (TED/Interface Sync).
