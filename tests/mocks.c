/**
 * @file mocks.c
 * @brief Stub implementations of HAL and dispatcher functions for unit tests.
 *
 * Every symbol that the PI layer calls but that lives in src/pd/ or
 * src/pi/rsvp_dispatcher.c is provided here so test binaries link cleanly
 * without pulling in Linux netlink or timerfd code.
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>

#include "common/rsvp_error.h"
#include "mocks.h"

/* ---------- Captured-packet state ---------------------------------------- */
uint8_t mock_captured_pkt[4096];
size_t  mock_captured_len  = 0;
int     mock_pkt_count     = 0;

/* ---------- Behavior knobs ----------------------------------------------- */
bool mock_is_local     = true;
int  mock_egress_ifidx = 5;

/* ---------- Call counters ------------------------------------------------ */
int mock_mpls_install_calls = 0;
int mock_mpls_remove_calls  = 0;

/* ---------- HAL: netlink ------------------------------------------------- */

int hal_netlink_get_egress_if(struct in_addr* dest, struct in_addr* next_hop) {
    *next_hop = *dest;
    return mock_egress_ifidx;
}

int hal_netlink_get_local_addr(int ifindex, struct in_addr* addr) {
    (void)ifindex;
    inet_aton("10.0.0.1", addr);
    return 0;
}

bool hal_netlink_is_local_addr(struct in_addr* addr) {
    (void)addr;
    return mock_is_local;
}

/* ---------- HAL: MPLS ---------------------------------------------------- */

int hal_mpls_install(uint32_t in_label, uint32_t out_label, int out_ifindex,
                     struct in_addr* next_hop, struct in_addr* dest_addr) {
    (void)in_label; (void)out_label; (void)out_ifindex;
    (void)next_hop; (void)dest_addr;
    mock_mpls_install_calls++;
    return 0;
}

int hal_mpls_remove(uint32_t in_label, struct in_addr* dest_addr) {
    (void)in_label; (void)dest_addr;
    mock_mpls_remove_calls++;
    return 0;
}

void hal_mpls_dump(void) {}

/* ---------- HAL: timer --------------------------------------------------- */

int  hal_timer_init(void)           { return 100; }
void hal_timer_set(uint32_t t)      { (void)t; }
void hal_timer_clear(void)          {}

/* ---------- Dispatcher: packet send -------------------------------------- */

rsvp_error_t rsvp_send_packet(struct in_addr* src, struct in_addr* dest,
                               uint8_t* buffer, size_t len, bool use_rao) {
    (void)src; (void)dest; (void)use_rao;
    if (len <= sizeof(mock_captured_pkt)) {
        memcpy(mock_captured_pkt, buffer, len);
        mock_captured_len = len;
    }
    mock_pkt_count++;
    return RSVP_SUCCESS;
}

/* ---------- Utility ------------------------------------------------------ */

void mock_reset(void) {
    mock_captured_len       = 0;
    mock_pkt_count          = 0;
    mock_mpls_install_calls = 0;
    mock_mpls_remove_calls  = 0;
    /* Leave is_local and egress_ifidx for the caller to set explicitly */
}
