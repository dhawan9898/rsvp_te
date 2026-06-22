# RSVP-TE Industrial Daemon

An industrial-grade, robust, and modular RSVP-TE (Resource Reservation Protocol - Traffic Engineering) daemon implementation for Linux. This project adheres to RFC 2205, 2209, and 3209, featuring a high-scale hierarchical wheel timer, a rtnetlink-based hardware/kernel data-plane abstraction, and an interactive command-line interface.

---

## Capabilities & Architecture

- **RFC Compliance**: Implements core signaling for RSVP (RFC 2205/2209) and RSVP-TE extensions (RFC 3209).
- **Hierarchical Wheel Timers**: Utilizes an $O(1)$ amortized hierarchical cascade wheel timer (`wheel_timer/`) for high-scale soft-state management.
- **Asynchronous, Non-Blocking Event Loop**: Powered by a unified `poll()` loop in `src/pi/rsvp_dispatcher.c` that multiplexes:
  - Command Line Interface (CLI) input
  - Raw RSVP sockets (IPv4 Protocol 46)
  - Linux rtnetlink sockets (for link, address, and egress routing events)
  - Thread-safe timer pipe signals
- **Secure Asynchronous Timer Processing**: Implements a main-thread active timer registry with generation sequence numbers to completely eliminate Use-After-Free (UAF) and ABA race conditions when timers expire concurrently during database mutations.
- **Hardware/Kernel Data Plane Programing**: Communicates with the Linux kernel via rtnetlink (`src/pd/hal_netlink_linux.c`) to query local interface configurations, perform egress route next-hop resolution, and program MPLS forwarding tables:
  - **MPLS Push (Ingress)**: Sets up an `encap mpls` IPv4 route for the tunnel destination IP.
  - **MPLS Swap (Transit)**: Injects MPLS route swaps for incoming-to-outgoing labels.
  - **MPLS Pop/Cleanups (Egress/Tear)**: Deletes routes during tunnel teardown or timeout.
- **Robust Soft-State Cleanup**: Automatic teardown of stale resources using jittered trigger/backup timers.
- **Error Spec Generation and Propagation**: Supports bidirectional generation and forwarding of `PathErr` and `ResvErr` messages with RFC-standard error codes.

---

## Usage

### Building

To build the daemon and tests with logging enabled (default):
```bash
make clean && make
```

To build without logging:
```bash
make clean && make DISABLE_LOGS=1
```

### Running the Daemon

```bash
sudo ./rsvp_daemon
```
*Note: `sudo` is required to open the raw IP socket (protocol 46) and manipulate kernel routing tables via Netlink.*

### CLI Commands

Once the daemon is running, you will be presented with the `rsvp-te>` prompt:
- `show psb`: Displays all active Path State Blocks.
- `show rsb`: Displays all active Reservation State Blocks.
- `show mpls routes`: Displays the local MPLS route cache including both ingress push tunnels and transit swaps.
- `setup tunnel <src_ip> <dest_ip> <tunnel_id> <name>`: Initiates a new RSVP-TE path from the ingress.
  - Example: `setup tunnel 10.0.0.1 10.0.0.2 1 test_tunnel`
- `delete tunnel <tunnel_id> <lsp_id>`: Triggers manual teardown of a path and reservation.
  - Example: `delete tunnel 1 1`
- `ping <src_ip> <dest_ip> <count>`: Executes a ping command bound to the source interface/IP to verify the MPLS encapsulation and datapath forwarding for the tunnel destination.
  - Example: `ping 10.0.0.1 10.0.0.2 5`

---

## RSVP & RSVP-TE Feature Checklist

Below is a detailed checklist of features supported by this daemon, indicating their compliance status for future enhancement references.

### 1. RSVP Core Signaling (RFC 2205 & RFC 2209)

| Feature | RFC Section | Status | Implementation Details / Limitations |
| :--- | :--- | :---: | :--- |
| **Path State Block (PSB) Management** | RFC 2205 Sec 3.1 | **Supported** | Tracked in state database with rolling hash. |
| **Resv State Block (RSB) Management** | RFC 2205 Sec 3.1 | **Supported** | Tracked in state database; triggers label binding. |
| **Blockade State Blocks (BSB)** | RFC 2209 | **Supported** | Implements blockade state and blockade timers ($T_b$) to prevent killer reservations. |
| **Soft-State Refresh & Jitter** | RFC 2205 Sec 3.7 | **Supported** | Powered by high-precision cascade timer wheel. Refresh interval jittered (0.8R to 1.2R). |
| **Soft-State State Cleanup** | RFC 2205 Sec 3.7 | **Supported** | Automated state expiry ($K \times R$ timeout) when refreshes cease. |
| **PathTear & ResvTear Propagation**| RFC 2205 Sec 3.8 | **Supported** | Bidirectional teardown propagation downstream and upstream. |
| **PathErr & ResvErr Propagation** | RFC 2205 Sec 3.9 | **Supported** | Generates, logs, and propagates error messages with standard error codes. |
| **Raw Socket IP Encap (Protocol 46)**| RFC 2205 Sec 4 | **Supported** | Uses `SOCK_RAW` socket. Binds Router Alert Option (RAO) for intermediate packet interception. |
| **RSVP UDP Encapsulation** | RFC 2205 Sec 4 | **Unsupported** | Only supports raw IP socket transmission. |
| **Integrity & Authentication** | RFC 2747 / 3097 | **Unsupported** | Parsing hooks exist for Integrity object, but MD5/HMAC verification is not implemented. |
| **IPv4 Address Family** | RFC 2205 | **Supported** | Full IPv4 support. |
| **IPv6 Address Family** | RFC 2205 | **Unsupported** | Protocol structures are declared but parsing and processing are unimplemented. |

### 2. RSVP Traffic Engineering Extensions (RFC 3209)

| Feature | RFC Section | Status | Implementation Details / Limitations |
| :--- | :--- | :---: | :--- |
| **Explicit Route Object (ERO)** | RFC 3209 Sec 4.3 | **Supported** | Parses strict sub-objects (IPv4 hops), pops local addresses, and resolves next-hop egress interfaces. |
| **Record Route Object (RRO)** | RFC 3209 Sec 4.4 | **Supported** | Collects actual traversed hops and records route info downstream. |
| **Label Request Object Signaling** | RFC 3209 Sec 4.1 | **Supported** | Mandatory check for new path establishments. |
| **Label Object Signaling** | RFC 3209 Sec 4.1 | **Supported** | Transmits allocated downstream labels upstream inside RESV messages. |
| **Label Allocation Pool** | RFC 3209 Sec 4.1 | **Supported** | Local bitmap-based dynamic allocator managing a pool of MPLS labels. |
| **Ingress Label Mapping (Push)** | RFC 3209 Sec 4.1 | **Supported** | Programs kernel routing tables via Netlink (`RTA_ENCAP`/`MPLS_IPTUNNEL_DST`) to push label for destination IP traffic. |
| **Transit Label Swapping (Swap)** | RFC 3209 Sec 4.1 | **Supported** | Inserts swap routing rules (`AF_MPLS` family) for label-to-label mappings toward the next-hop. |
| **Egress Label Popping (Pop / PHP)** | RFC 3209 Sec 4.1 | **Partially** | Implicit-null and popping behavior is handled on kernel data-planes; control-plane tracks egress pop states. |
| **Admission Control & QoS Accounting**| RFC 3209 Sec 2 | **Partially** | Parses flowspecs/TSpec rate-limits, but lacks interface-level bandwidth booking and enforcement. |
| **LSP Session Attributes** | RFC 3209 Sec 4.7 | **Supported** | Parses setup/holding priorities and maps LSP names. |
| **FRR & Local Protection** | RFC 4090 | **Unsupported** | Fast Reroute (facility or one-to-one backup) is not implemented. |
| **Graceful Restart** | RFC 3473 Sec 9 | **Unsupported** | Missing helper recovery modes and hello keep-alive handshakes. |

---

## Code Directory Walkthrough

- `src/main.c`: Daemon entry point, logger boot, database init, and event loop activation.
- `src/common/`: Shared structures:
  - `rsvp_protocol.h`: Wire-format RSVP and RSVP-TE packet headers and objects.
  - `rsvp_error.h`: System-wide error status codes.
  - `rsvp_log.c`: Thread-safe file logging.
- `src/pi/`: Protocol-independent engine:
  - `rsvp_state_machine.c`: RFC-compliant state changes, ERO lookups, and signaling procedures.
  - `rsvp_dispatcher.c`: Multiplexing poll event loop and raw socket IP transmission.
  - `rsvp_parser.c` & `rsvp_builder.c`: RSVP message decoding and encoding.
  - `rsvp_state_db.c`: Memory database managing PSB, RSB, and BSB hash maps.
  - `rsvp_timers.c`: Bridge between state timers and the cascade wheel timer.
  - `label_mgr.c`: MPLS label bitmap allocator.
  - `rsvp_cli.c`: Interactive shell terminal processor.
- `src/pd/`: Platform-dependent implementations:
  - `hal_netlink_linux.c`: Linux-specific rtnetlink programming for MPLS and routing rules.
  - `hal_timer_linux.c`: Central timer wrapper using `timerfd`.
- `wheel_timer/`: High-performance $O(1)$ cascade timer wheel library using pthread workers.

---

## Restrictions & Assumptions

1. **Root Privileges**: The daemon requires root permissions (`sudo`) to create raw protocol sockets and invoke rtnetlink route injections.
2. **Direct Adjacency**: The daemon assumes that next hops are directly reachable on the link level.
3. **Single-Threaded Control Logic**: While the timer system uses background workers, the state-machine operations run strictly single-threaded inside the main event loop context to preserve state DB integrity without mutex overhead.

---

## Licensing
This project is provided for industrial prototyping, testing, and research purposes.
