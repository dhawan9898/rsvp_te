# RSVP-TE Industrial-Grade Code Review

This document provides a comprehensive review of the RSVP-TE daemon codebase against RFC 2205 (RSVP), RFC 2209 (Design), and RFC 3209 (RSVP-TE).

## 1. Executive Summary

The current implementation provides a solid foundation for RSVP-TE signaling with a modular design, hierarchical wheel timers, and platform abstraction. However, to be truly "industrial-ready," the codebase requires stricter adherence to RFC error handling, more robust object validation, and expanded support for mandatory/optional TE objects.

---

## 2. Detailed Findings & Suggestions

### 2.1. Parser & Builder (Strictness & Robustness)

| Component | Finding | RFC Reference | Severity | Suggestion |
| :--- | :--- | :--- | :--- | :--- |
| **Object Ordering** | The parser does not enforce the RFC-mandated object order for PATH/RESV messages. | RFC 2205 Sec 3.1 | Medium | Implement a state-aware parser that validates the sequence of incoming objects. |
| **Checksum Logic** | While fixed recently, the checksum calculation should ideally use a `uint32_t` accumulator throughout to avoid potential overflow issues before the final fold. | RFC 1071 / 2205 | Low | Refine `rsvp_checksum` for maximum portable precision. |
| **Unknown Objects** | The parser currently logs unhandled objects but doesn't implement the RFC "Class-Num" behavior (e.g., ignore vs. reject). | RFC 2205 Sec 3.10 | High | Implement the 2-bit 'c' field logic: 00 (reject), 01 (ignore), 10/11 (reserved). |
| **Buffer Lengths** | `rsvp_builder_add_session_attribute` has a hardcoded limit of 200 bytes for names. | RFC 3209 | Low | Dynamic sizing or strict RFC-max validation (up to 255) is preferred. |

### 2.2. State Machine (Compliance & Reliability)

| Component | Finding | RFC Reference | Severity | Suggestion |
| :--- | :--- | :--- | :--- | :--- |
| **Soft State Jitter** | Jitter is implemented, but the refresh interval $R$ should ideally be configurable per interface or session as per RFC. | RFC 2205 Sec 3.7 | Medium | Move `RSVP_REFRESH_MS` to a configuration block or per-PSB state. |
| **PathErr/ResvErr** | Error messages often use simplified local node lookups and generic error values. | RFC 2205 Sec 3.1.4 | High | Populate `ERROR_SPEC` with more granular codes (e.g., Code 2, Value 5 for 'No Label') and ensure the `error_node` is correctly identified. |
| **Tear Propagation** | `rsvp_psb_cleanup` propagates `PathTear` only if it's not the egress. It should ensure the full path is notified reliably even under high load. | RFC 2205 Sec 3.5 | Medium | Add retransmission or 'reliable delivery' logic for Tear messages (RFC 2961). |
| **Label Request** | Validation for `LABEL_REQUEST` is present but doesn't check for L3PID consistency across nodes. | RFC 3209 Sec 4.1 | Medium | Ensure L3PID (e.g., 0x0800 for IPv4) is verified against local capabilities. |

### 2.3. System & HAL (Industrial Readiness)

| Component | Finding | RFC Reference | Severity | Suggestion |
| :--- | :--- | :--- | :--- | :--- |
| **Security** | Current implementation lacks any form of message integrity. | RFC 2747 | Critical | **Priority 1:** Implement RSVP Authentication (MD5) to prevent spoofed PathTear/ResvErr attacks. |
| **MTU / Fragmentation** | The dispatcher uses a fixed 4096-byte buffer. RSVP packets can exceed MTU if many EROs/RROs are present. | RFC 2205 Sec 3.9 | Medium | Handle IP fragmentation or implement PMTU discovery for RSVP neighbors. |
| **Thread Safety** | While logically single-threaded, the interaction with `wheel_timer` worker threads needs rigorous checking for potential race conditions during high-frequency refreshes. | RFC 2209 | High | Audit the `pipe` mechanism for timer expirations to ensure no pointers are invalidated before processing. |

---

## 3. Roadmap for Industrial Hardening

### Phase 1: Security & Compliance (Next 2 Weeks)
1. **Authentication:** Add `INTEGRITY` object support (RFC 2747).
2. **Strict Parser:** Enforce object ordering and 'c' field behavior.
3. **Enhanced Errors:** Map every protocol failure to a specific RFC 2205 Error Code/Value.

### Phase 2: Traffic Engineering (Next 4 Weeks)
1. **ERO/RRO:** Implement Explicit Route and Record Route objects for path pinning and loop detection.
2. **Admission Control:** Add a hook for bandwidth reservation logic (RSVP-TE).

### Phase 3: Reliability & Scale (Next 8 Weeks)
1. **Reliable Messaging:** Implement RFC 2961 (RSVP Refresh Reduction/Reliability).
2. **Graceful Restart:** Implement RFC 3473 (Graceful Restart for RSVP-TE).

---

## 4. Conclusion

The daemon is **Functional** but not yet **Hardened**. By addressing the high-severity items (Security, Error Precision, and Strict Parsing), the implementation will transition from a prototype to a reliable industrial networking tool.
