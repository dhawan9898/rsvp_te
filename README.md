# RSVP-TE Daemon

A modular, RFC-compliant RSVP-TE (Resource Reservation Protocol — Traffic Engineering) daemon for Linux. Implements core RSVP signaling (RFC 2205/2209), RSVP-TE extensions (RFC 3209), Hello liveness (RFC 3209 §5.3), Fast ReRoute facility-backup (RFC 4090), and Make-Before-Break re-optimization.

---

## Feature Summary

| Area | RFC | Status |
|------|-----|--------|
| PATH / RESV / Tear / Err message handling | RFC 2205 | Supported |
| Soft-state refresh with jitter | RFC 2205 §3.7 | Supported |
| Blockade State Blocks (killer-reservation prevention) | RFC 2209 | Supported |
| Explicit Route Object (ERO) — IPv4 strict hops | RFC 3209 §4.3 | Supported |
| Record Route Object (RRO) | RFC 3209 §4.4 | Supported |
| Label Request / Label Object | RFC 3209 §4.1 | Supported |
| MPLS label allocation pool | RFC 3209 §4.1 | Supported |
| MPLS Push (ingress), Swap (transit), Pop (egress) | RFC 3209 §4.1 | Supported |
| LSP Session Attributes (setup/holding priority, name) | RFC 3209 §4.7 | Supported |
| RSVP Hello — neighbor liveness detection | RFC 3209 §5.3 | Supported |
| Per-interface bandwidth management (8 priorities) | RFC 2209 §2.2 | Supported |
| FRR facility-backup (bypass tunnels, PLR auto-arm) | RFC 4090 | Supported |
| FRR auto-association at transit PLR | RFC 4090 | Supported |
| FRR revert after link recovery | RFC 4090 | Supported |
| Make-Before-Break re-optimization | RFC 3209 §6.6 | Supported |
| Graceful shutdown (PathTear / ResvTear on SIGTERM) | RFC 2205 | Supported |
| Raw socket encapsulation (IP protocol 46) | RFC 2205 §4 | Supported |
| Router Alert Option for PATH/RESV | RFC 2113 | Supported |
| IPv6 address family | RFC 2205 | Unsupported |
| RSVP UDP encapsulation | RFC 2205 §4 | Unsupported |
| Integrity / authentication | RFC 2747 | Unsupported |

---

## Architecture

```
src/
├── main.c                  Daemon entry point, signal handling, event loop
├── common/
│   ├── rsvp_protocol.h     Wire-format structs for all RSVP objects
│   ├── rsvp_error.h        Error code enumeration
│   └── rsvp_log.c/h        Thread-safe file logger
├── pi/                     Protocol-Independent engine
│   ├── rsvp_state_machine.c/h  Core FSM: PATH/RESV/Tear/Err handlers,
│   │                           ERO routing, FRR trigger/revert/dump,
│   │                           Make-Before-Break (rsvp_mbb_start)
│   ├── rsvp_dispatcher.c/h     poll() event loop, raw socket I/O
│   ├── rsvp_parser.c/h         RSVP message decoder → rsvp_message_info
│   ├── rsvp_builder.c/h        RSVP message encoder
│   ├── rsvp_state_db.c/h       PSB / RSB / BSB hash-table database
│   ├── rsvp_state.h            State block struct definitions
│   ├── rsvp_timers.c/h         Soft-state timer bridge (wheel timer)
│   ├── label_mgr.c/h           MPLS label bitmap allocator
│   ├── rsvp_hello.c/h          Hello subsystem (RFC 3209 §5.3)
│   ├── rsvp_if.c/h             Per-interface RSVP state and BW accounting
│   └── rsvp_cli.c/h            Interactive CLI command processor
├── pd/                     Platform-Dependent implementations
│   ├── hal_netlink_linux.c Linux rtnetlink: route lookup, MPLS programming
│   └── hal_timer_linux.c   timerfd-based hardware timer
wheel_timer/                O(1) hierarchical cascade timer wheel (pthread)
tests/                      Unit and functional test suite
└── test_rsvp.c             Legacy integration test (retained)
```

### Event Loop

The dispatcher (`rsvp_dispatcher.c`) runs a single-threaded `poll()` loop that
multiplexes four event sources:

1. **Raw RSVP socket** (IP protocol 46) — incoming PATH/RESV/Hello/Tear/Err
2. **CLI stdin** — interactive operator commands
3. **rtnetlink socket** — link-up/down events for FRR revert triggering
4. **Timer pipe** — wheel timer expiry signals

All state machine operations execute on this single thread, eliminating the
need for locks on the PSB/RSB databases.

### Soft-State and Timers

Each PSB and RSB carries two wheel-timer instances:
- **Refresh timer** — fires at `R × jitter(0.8–1.2)` to re-send PATH or RESV
- **Cleanup timer** — fires at `K × R` (default K = 3) to expire stale state

The wheel timer library (`wheel_timer/`) provides O(1) amortized insert and
expiry using a hierarchical cascade structure backed by a dedicated pthread.
Timer callbacks are delivered to the main thread via a pipe to stay
single-threaded.

### RSVP Hello (RFC 3209 §5.3)

The Hello subsystem (`rsvp_hello.c`) maintains up to 128 neighbors:
- Sends Hello REQUEST every 5 s; declares neighbor DOWN after 15 s (3 × interval)
- Each neighbor carries a stable `src_instance` (random non-zero); a changed
  `src_instance` in a received Hello signals a neighbor restart
- Neighbor DOWN event calls `rsvp_frr_trigger()` for all LSPs egressing that
  interface, enabling sub-second failover

### Fast ReRoute (RFC 4090 — Facility Backup)

1. **Bypass tunnel setup**: `rsvp_initiate_bypass_tunnel()` signals an LSP that
   avoids a specific protected interface (PLR → merge point)
2. **Auto-association at PLR**: when a transit node receives PATH+FAST_REROUTE,
   `rsvp_frr_auto_associate()` scans for a ready bypass covering the egress
   interface and arms protection automatically — no manual operator step needed
3. **Bypass UP hook**: when a bypass RESV is first installed,
   `rsvp_frr_auto_associate_all()` retroactively arms any LSPs that were waiting
4. **Trigger**: `rsvp_frr_trigger(ifindex)` reprograms MPLS forwarding to bypass
   labels and re-sends PATH with LOCAL_PROTECTION_IN_USE
5. **Revert**: `rsvp_frr_revert(ifindex)` restores original forwarding after link
   recovery and re-sends PATH without LOCAL_PROTECTION_IN_USE

### Make-Before-Break (RFC 3209 §6.6)

`rsvp_mbb_start(tunnel_id, old_lsp_id, new_lsp_id, ero, ero_count)` creates a
new LSP with the same Session (tunnel_id) but a fresh LSP-ID. The incumbent
path stays active throughout. When the new path's first RESV arrives
(`is_mbb_pending == true`), `rsvp_mbb_complete()` atomically tears down the
old path — zero traffic interruption.

---

## Building

```bash
# Build daemon and legacy integration test
make

# Build all unit tests (no root required)
make tests

# Run the full test suite
make check

# Build without logging (smaller binary)
make DISABLE_LOGS=1
```

### Dependencies

- GCC with C11 support
- Linux kernel headers (`<linux/rtnetlink.h>`, `<linux/mpls.h>`)
- pthreads (`-lpthread`)
- libm (`-lm`)

---

## Running

```bash
sudo ./rsvp_daemon
```

Root privileges are required to open a raw IP socket (protocol 46) and inject
MPLS routes via rtnetlink.

---

## CLI Commands

Once the daemon is running, the `rsvp-te>` prompt accepts:

### Show commands
```
show psb                          — All active Path State Blocks
show rsb                          — All active Reservation State Blocks
show mpls routes                  — Local MPLS route cache
show rsvp neighbors               — Hello neighbor state table
show rsvp interfaces              — All RSVP-enabled interfaces
show rsvp interface <name>        — Detailed per-interface info
show rsvp frr                     — FRR protection status table
```

### Interface configuration
```
interface <name> rsvp enable
interface <name> rsvp disable
interface <name> rsvp neighbor <ip>
interface <name> bandwidth <Mbps>
interface <name> reservable-bandwidth <Mbps>
interface <name> hello-interval <ms>
```

### Tunnel operations
```
setup tunnel <src_ip> <dest_ip> <tunnel_id> <name>
delete tunnel <tunnel_id> <lsp_id>
```

### FRR and MBB
```
rsvp frr revert <ifindex>                       — Revert after link recovery
rsvp mbb <tunnel_id> <old_lsp_id> <new_lsp_id>  — Start MBB re-optimization
```

---

## Test Suite

Tests live in `tests/` and build independently of the daemon — no Linux netlink
or timerfd. All platform-dependent HAL functions are replaced by stubs in
`tests/mocks.c`.

| Binary | What it covers |
|--------|----------------|
| `tests/test_builder` | Message encoding: field values, byte order, buffer overflow |
| `tests/test_parser` | Message decoding: PATH, RESV, Hello, ERO, truncation rejection |
| `tests/test_state_db` | PSB/RSB/BSB hash-table CRUD, find-by-id, bucket iterator |
| `tests/test_label_mgr` | Label pool: alloc, free, exhaustion, reinit |
| `tests/test_if` | Interface enable/disable, BW config, reserve/release, available-BW |
| `tests/test_hello` | Neighbor lifecycle, state transitions, ACK response, restart detection |
| `tests/test_state_machine` | Full PATH→RESV→Tear functional flows, MPLS install/remove verification |
| `tests/test_mbb_frr` | MBB lifecycle, FRR protection API, trigger/revert smoke tests |

```bash
make check        # build all + run + summarize
```

Each binary exits 0 on full pass and 1 on any failure. `make check` prints a
final pass/fail count across all binaries.

---

## State Machine Data Flow

```
Ingress (head-end)
  rsvp_initiate_path()
       │  PATH →
       ▼
Transit node(s)
  handle_path_message()  — create PSB, pop ERO hop, forward PATH
  handle_resv_message()  — create RSB, allocate label, swap MPLS, forward RESV
       │  ← RESV
       ▼
Egress (tail-end)
  handle_path_message()  — create PSB, allocate label_in, send RESV upstream
  hal_mpls_install()     — Push (ingress) or Pop (egress) rule programmed
```

---

## Notes and Constraints

- **Root required** for raw sockets and rtnetlink MPLS route injection
- **Single-threaded control plane** — all FSM operations run on the dispatcher
  thread; no locks needed on state blocks
- **Soft-state model** — state expires if refreshes stop; explicit tears are
  optimizations, not requirements
- **IPv4 only** — IPv6 session objects are parsed but not processed
- **Direct adjacency** — next hops are assumed to be on directly connected
  links; recursive resolution is not implemented
