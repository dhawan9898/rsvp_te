# RSVP-TE Code Review

This review covers functional correctness, robustness, memory/resource handling, and design issues discovered in the current `rsvp_te` codebase.

## 1. Build / Compile Issues

- `src/hal/hal_netlink.h` uses `bool` but does not include `<stdbool.h>`.
- `src/pd/hal_netlink_linux.c` also uses `bool`, `true`, and `false` without including `<stdbool.h>`.
- Warnings in `src/pi/rsvp_parser.c` about casting a packed struct pointer to `uint16_t *` for checksum computation.
- Warnings in `src/pd/hal_timer_linux.c` about unused callback parameters.

## 2. Functional and Protocol Errors

### 2.1 RSVP Parsing
- `rsvp_parse_packet()` does not validate the IPv4 header beyond `ihl` and may dereference invalid memory if the input is malformed.
- The parser uses `obj_len = ntohs(obj_hdr->length)` but does not validate object payload length against `obj_len` before dereferencing object data.
- RSVP objects are advanced using `obj_len`, but the builder pads objects to 4-byte boundaries using `RSVP_ALIGN()`. The parser does not skip padding, so it can lose packet synchronization for padded objects.
- Mandatory RSVP objects are not enforced. The function returns success even if required `SESSION` or `SENDER_TEMPLATE` objects are missing.
- `SESSION_ATTRIBUTE` object parsing copies `name_length` bytes without validating `obj_len` is large enough.

### 2.2 RSVP Message Building
- `rsvp_builder_add_label_ipv4()` shifts label bits but never validates label size or reserves fields properly.
- `rsvp_builder_add_tspec()` writes floating-point fields directly into network byte order data without byte-order conversion, which is incorrect for wire format bytes on little-endian platforms.
- `rsvp_builder_init()` sets only `ver_flags`, `msg_type`, and `ttl` but does not initialize `length` or `checksum` explicitly until `finalize()`, leaving the header in an indeterminate state if other code inspects it early.

### 2.3 State Machine Logic
- `label_mgr_free()` is a no-op, so labels are never reused and label space leaks immediately.
- `rsvp_state_machine.c` uses `rsb->label_out = ntohl(info->label->label);` without extracting the 20-bit MPLS label field (`label >> 12`). This stores the raw wire format value.
- `send_resv_upstream()` sends a default label `3` when `rsb->label_in` is zero, which is almost certainly invalid for RSVP-TE label semantics.
- `rsvp_initiate_path()` sets a constant `lsp_id = 1` for every source, meaning multiple LSPs from the same source will collide.
- `handle_path_message()` does not populate `psb->ifindex_in` for transit/path state.
- `rsb_refresh_timer_cb()` only reinserts the timer and does not send actual refresh messages, so timer behavior is incomplete.
- `psb_cleanup_timer_cb()` and `rsb_cleanup_timer_cb()` remove state but do not fully clear associated pointers in all cases, which can leave stale references if asynchronous timer callbacks race.
- `handle_path_err()` and `handle_resv_err()` propagate error packets without decrementing TTL or recomputing checksum.
- `propagate_path_tear()` and `propagate_resv_tear()` are marked TODO and therefore the tear-down path is not implemented.

### 2.4 Networking / HAL Issues
- `rsvp_dispatcher_run()` does not handle `POLLERR`, `POLLHUP`, or `POLLNVAL`, and it ignores errors on timer file descriptors.
- Raw socket use with `AF_INET, SOCK_RAW, RSVP_PROTOCOL` requires root and may require explicit `IP_HDRINCL`; the code does not document or guard this.
- `hal_netlink_get_egress_if()` uses `IFA_PAYLOAD(nh)` for route messages, which is incorrect; route messages should use `RTM_PAYLOAD()` or `NLMSG_PAYLOAD()`.
- `hal_netlink_get_egress_if()` uses a separate temporary netlink socket, but does not validate message sequence, and only processes the first message.
- `hal_netlink_process()` caches interface addresses in a fixed-size array indexed with `ifa_index % MAX_INTERFACES`, causing collisions and incorrect address storage for ifindexes >= 32.
- `hal_netlink_get_local_addr()` repeatedly calls `if_nametoindex()` inside a loop instead of using the cached `ifa_index` or comparing names once.
- `hal_netlink_is_local_addr()` does a full `getifaddrs()` walk on every call instead of using cached address state.

## 3. Resource / Leak Risks

- `label_mgr_alloc()` never reuses released labels; `label_mgr_free()` is unimplemented.
- `rsvp_timer_start()` creates timerfds via `hal_timer_add()` but `rsvp_timer_handle_exp()` only calls `read()` without checking for partial read or error conditions.
- If `rsvp_timer_handle_exp()` receives `read()` failure, the timer may remain active and keep firing.
- `rsvp_state_db` structures are dynamically allocated, but deletion paths are incomplete if timers or state cleanup fail.

## 4. Robustness and Security Issues

- `main()` does not validate `inet_aton()` return values before using the parsed addresses.
- `strncpy(dest_str, inet_ntoa(*dest), INET_ADDRSTRLEN);` is unnecessary and introduces potential string-handling complexity.
- `rsvp_builder_add_session_attribute()` silently truncates names longer than 200 bytes instead of returning an error.
- The code lacks bounds checking for malformed packets in many object handlers.
- The code uses packed structs and then casts to wider pointers for checksum operations, triggering alignment warnings and risking undefined behavior on architectures with strict alignment.

## 5. Design and Maintainability Issues

- `label_mgr.c` is a stub implementation with a TODO placeholder; this is a fundamental protocol resource manager and must be completed before the system is production-ready.
- Timer logic is only partially implemented and does not support reset semantics or multi-shot operation.
- Many key RSVP behaviors are unimplemented or stubbed (`propagate_path_tear()`, `propagate_resv_tear()`, refresh retransmission, explicit route handling).
- The state database uses a simple hash table without load factor management or rehashing.
- There is no logging abstraction; protocol logic prints directly to `stdout`/`stderr`, which will not scale in a daemon.

## 6. Recommended Priority Fixes

1. Fix build errors by adding `<stdbool.h>` to `src/hal/hal_netlink.h` and `src/pd/hal_netlink_linux.c`.
2. Implement `label_mgr_free()` and proper label reuse, or replace with a real bitmap/free-list manager.
3. Harden `rsvp_parse_packet()` to validate object lengths, handle padding with `RSVP_ALIGN()`, and reject malformed packets.
4. Correct RSVP label extraction in `rsvp_state_machine.c` and remove the invalid default label `3` behavior.
5. Fix `rsvp_builder_add_tspec()` to serialize TSpec fields in network byte order correctly.
6. Correct netlink route parsing in `hal_netlink_get_egress_if()` and handle multipart responses safely.
7. Improve timer handling: validate `read()`, handle `POLLERR`, and implement reset/retransmission semantics.
8. Add explicit error handling around `inet_aton()` and raw socket initialization.

## 7. Summary

The current implementation shows a valid high-level structure, but there are several serious protocol and robustness gaps:

- RSVP packet parsing/building is not fully RFC-safe and will mishandle padded objects, malformed packets, and TSpec serialization.
- The RSVP state machine is incomplete and contains label semantics bugs, missing refresh behavior, and unimplemented teardown propagation.
- The HAL/netlink layer is fragile and has both build-time and runtime parsing problems.
- Resource management is not complete: label freeing is a no-op, and timer cleanup is weak.

## 8. Fixes Applied

- Added missing `<stdbool.h>` includes in `src/hal/hal_netlink.h` and `src/pd/hal_netlink_linux.c`.
- Hardened `src/pi/rsvp_parser.c` with packet-length validation, padded object parsing, and checksum verification without alignment violations.
- Updated `src/pi/rsvp_builder.c` to serialize RSVP fields in network byte order and to compute checksums from raw bytes.
- Implemented label allocation and reuse in `src/pi/label_mgr.c`.
- Corrected RSVP state key and LSP ID handling in `src/pi/rsvp_state_machine.c`.
- Improved dispatcher poll handling and timer expiration robustness in `src/pi/rsvp_dispatcher.c` and `src/pi/rsvp_timers.c`.
- Fixed Netlink route lookup and interface caching in `src/pd/hal_netlink_linux.c`.
- Added minimal `PathTear` and `ResvTear` forwarding support in `src/pi/rsvp_state_machine.c`.

If you want, I can continue with RFC-compliance testing or add static analysis unit tests for the RSVP parser and label manager.