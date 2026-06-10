# RSVP-TE Daemon

A lightweight RSVP-TE (Resource Reservation Protocol - Traffic Engineering) daemon implementation for Linux. This application manages LSP (Label Switched Path) state, performs label allocation, and interacts with the Linux kernel via Netlink for route and interface management.

## Architecture

The project is divided into several layers:

### 1. Common Layer (`src/common/`)
- `rsvp_protocol.h`: RSVP-TE message and object structure definitions as per RFC 2205 and RFC 3209.
- `rsvp_log.c/h`: Basic logging utility.

### 2. PI Layer (Protocol Independent) (`src/pi/`)
- `rsvp_dispatcher.c/h`: Main event loop using `poll()`. Handles raw RSVP sockets, Netlink sockets, and timers.
- `rsvp_parser.c/h`: Robust RSVP packet parsing and validation.
- `rsvp_builder.c/h`: RSVP message construction and serialization.
- `rsvp_state_machine.c/h`: Core RSVP-TE state machine logic (PATH/RESV handling).
- `rsvp_state_db.c/h`: Database for storing PSB (Path State Block) and RSB (Resv State Block).
- `label_mgr.c/h`: MPLS label allocation and management.
- `rsvp_timers.c/h`: RSVP-specific timer management (Refresh/Cleanup).

### 3. PD Layer (Protocol Dependent / HAL) (`src/pd/`, `src/hal/`)
- `hal_netlink_linux.c`: Linux-specific Netlink implementation for interface and route discovery.
- `hal_timer_linux.c`: Linux `timerfd` based timer implementation.
- `hal/`: HAL headers defining the interface between PI and PD layers.

## Build System

The project uses a standard `Makefile`.

### Prerequisites
- GCC
- Make
- Linux Kernel headers (for Netlink and Raw sockets)

### Compilation
To build both the daemon and the test utility:
```bash
make all
```

To clean the build artifacts:
```bash
make clean
```

## Running the Application

### RSVP Daemon
The daemon requires root privileges to open raw sockets and interact with Netlink.
```bash
sudo ./rsvp_daemon
```

### Verification Test
A standalone test program `test_rsvp` is provided to verify the RSVP logic in a simulated environment.
```bash
./test_rsvp
```

## Key Features

- **Robust Parsing**: Handles padded RSVP objects and validates checksums.
- **Manual IP Header Construction**: Uses `IP_HDRINCL` to support the Router Alert Option (RAO) and precise source IP control.
- **State Management**: Full implementation of PSB and RSB state blocks with associated refresh and cleanup timers.
- **MPLS Integration**: Ready for MPLS programming via HAL (stubs provided for actual hardware/kernel installation).
- **Label Management**: Dynamic allocation and reuse of MPLS labels.

## Documentation
- `CODE_REVIEW.md`: Detailed review of the codebase, including applied fixes and future improvements.
- `RSVP_TE_DESIGN.md`: Initial design considerations and architecture overview.
