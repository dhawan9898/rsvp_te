# RSVP-TE Industrial Daemon (Refactored)

An industrial-grade, robust, and modular RSVP-TE (Resource Reservation Protocol - Traffic Engineering) daemon implementation for Linux. This project adheres to RFC 2205, 2209, and 3209, featuring a hierarchical wheel timer and a command-line interface.

## Capabilities

- **RFC Compliance**: Implements core signaling for RSVP (RFC 2205/2209) and TE extensions (RFC 3209).
- **Hierarchical Wheel Timers**: Uses an $O(1)$ amortized hierarchical wheel timer for high-scale soft-state management (Refresh and Cleanup timers).
- **Asynchronous Event Loop**: Powered by a non-blocking `poll()` loop that multiplexes raw sockets, timer events, and CLI input.
- **Platform Abstraction (PI/PD)**: Clean separation between Platform Independent (protocol logic) and Platform Dependent (Linux Netlink, Raw Sockets) code.
- **MPLS Integration**: Interfaces with the Linux kernel via Netlink to program MPLS label swapping and routing.
- **Interactive CLI**: Real-time inspection of PSB (Path State Blocks) and RSB (Reservation State Blocks).

## Project Structure

- `src/main.c`: Entry point and initialization.
- `src/common/`: Common headers for protocol definitions, logging, and error handling.
- `src/pi/`: Platform Independent logic.
    - `rsvp_state_machine.c`: Core RFC logic for Path/Resv processing.
    - `rsvp_timers.c`: Bridge between protocol state and the wheel timer.
    - `rsvp_cli.c`: Command parser and state dumper.
- `src/pd/`: Platform Dependent implementation.
    - `hal_netlink_linux.c`: Linux-specific MPLS/route programming.
- `wheel_timer/`: High-performance hierarchical timer library.

## Usage

### Building
```bash
make clean && make
```

### Running the Daemon
```bash
sudo ./rsvp_daemon
```
*Note: sudo is required for raw socket access and Netlink routing table manipulation.*

### CLI Commands
Once the daemon is running, you will see the `rsvp-te>` prompt:
- `show psb`: Displays all active Path State Blocks.
- `show rsb`: Displays all active Reservation State Blocks.
- `setup tunnel <src_ip> <dest_ip> <tunnel_id> <name>`: Initiates a new RSVP-TE path.
  - Example: `setup tunnel 192.168.1.1 192.168.1.2 100 tunnel_test`

## Code Walkthrough: Timer Integration
The integration of the `wheel_timer` is handled via a thread-safe pipe mechanism in `src/pi/rsvp_timers.c`. 
1. The `wheel_timer` worker threads execute callbacks upon expiration.
2. The callback writes the `rsvp_timer_t` pointer to a pipe.
3. The main `poll()` loop in `rsvp_dispatcher.c` detects the pipe activity and executes the protocol-level callback in the main thread context, ensuring no race conditions on state blocks.

## Restrictions & Assumptions
- **IPv4 Only**: Current implementation is focused on IPv4 LSPs.
- **Linux Specific**: The HAL is implemented for Linux (Raw Sockets & Netlink).
- **Single Threaded PI**: Protocol logic is single-threaded for simplicity and lock-free state management.
- **Direct Adjacency**: Assumes neighbors are directly reachable for the raw socket transmission.

## Licensing
This project is provided for educational and industrial prototyping purposes.
