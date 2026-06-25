/**
 * @file mocks.h
 * @brief Shared mock state for RSVP-TE unit tests.
 *
 * mocks.c provides stub implementations of every platform-dependent function
 * (HAL, send) so that PI test binaries can link without pulling in Linux
 * netlink or timerfd code.  Test files control behavior via the variables
 * exported here.
 */

#ifndef MOCKS_H
#define MOCKS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---------- Captured-packet state ----------------------------------------
 * rsvp_send_packet() stores the last sent packet here so tests can parse and
 * inspect what the state machine produced.
 */
extern uint8_t mock_captured_pkt[4096];
extern size_t  mock_captured_len;
extern int     mock_pkt_count;   /**< total calls to rsvp_send_packet() */

/* ---------- Behavior knobs -----------------------------------------------
 * Tests flip these before exercising a code path.
 */
extern bool mock_is_local;      /**< hal_netlink_is_local_addr() return value */
extern int  mock_egress_ifidx;  /**< hal_netlink_get_egress_if() return value  */

/* ---------- Call counters ------------------------------------------------ */
extern int mock_mpls_install_calls;
extern int mock_mpls_remove_calls;

/** Reset captured-packet state and call counters.  Does NOT change knobs. */
void mock_reset(void);

#endif /* MOCKS_H */
