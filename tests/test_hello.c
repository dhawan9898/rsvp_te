/**
 * @file test_hello.c
 * @brief Unit tests for rsvp_hello — RSVP Hello neighbor liveness (RFC 3209 §5.3).
 *
 * Tests cover: neighbor creation, find, recv REQUEST/ACK state transitions,
 * ACK send-back on REQUEST, and restart detection (changed src_instance).
 *
 * rsvp_frr_trigger() is provided as a local stub because this test binary
 * does not link rsvp_state_machine.c (no PATH/RESV processing needed).
 */

#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "test_framework.h"
#include "pi/rsvp_hello.h"
#include "mocks.h"

/* Stub so hello.c can call rsvp_frr_trigger() without linking the full SM */
static int g_frr_trigger_calls = 0;
void rsvp_frr_trigger(uint32_t failed_ifindex) {
    (void)failed_ifindex;
    g_frr_trigger_calls++;
}

/* ---------- helpers ------------------------------------------------------ */

static struct in_addr ip(const char* s) {
    struct in_addr a;
    inet_aton(s, &a);
    return a;
}

/* ---------- tests -------------------------------------------------------- */

static void test_add_neighbor_creates_entry(void) {
    TEST_BEGIN("add_neighbor_creates_entry");
    rsvp_hello_init();

    struct in_addr nbr   = ip("10.0.0.2");
    struct in_addr local = ip("10.0.0.1");
    struct rsvp_neighbor* n = rsvp_hello_add_neighbor(&nbr, &local, 1);

    ASSERT_NOTNULL(n, "add_neighbor returns non-NULL");
    ASSERT_EQ(n->addr.s_addr, nbr.s_addr, "neighbor IP stored correctly");
    ASSERT_EQ(n->ifindex, 1u, "ifindex stored correctly");
    ASSERT_EQ(n->state, RSVP_NBOR_IDLE, "initial state is IDLE");

    rsvp_hello_shutdown();
}

static void test_add_neighbor_idempotent(void) {
    TEST_BEGIN("add_neighbor_idempotent");
    rsvp_hello_init();

    struct in_addr nbr   = ip("10.0.0.3");
    struct in_addr local = ip("10.0.0.1");
    struct rsvp_neighbor* a = rsvp_hello_add_neighbor(&nbr, &local, 2);
    struct rsvp_neighbor* b = rsvp_hello_add_neighbor(&nbr, &local, 2);

    ASSERT_EQ(a, b, "second add_neighbor returns same pointer");

    rsvp_hello_shutdown();
}

static void test_find_returns_null_for_unknown(void) {
    TEST_BEGIN("find_returns_null_for_unknown");
    rsvp_hello_init();

    struct in_addr addr = ip("192.168.1.99");
    ASSERT_NULL(rsvp_hello_find_neighbor(&addr), "find returns NULL for unknown neighbor");

    rsvp_hello_shutdown();
}

static void test_recv_request_transitions_to_up(void) {
    TEST_BEGIN("recv_request_transitions_to_up");
    rsvp_hello_init();
    mock_reset();

    struct in_addr nbr   = ip("10.0.0.4");
    struct in_addr local = ip("10.0.0.1");
    rsvp_hello_add_neighbor(&nbr, &local, 3);

    /* Simulate receiving a Hello REQUEST from this neighbor */
    rsvp_hello_recv(&nbr, 0xABCD1234, 0, RSVP_HELLO_CTYPE_REQUEST);

    struct rsvp_neighbor* n = rsvp_hello_find_neighbor(&nbr);
    ASSERT_NOTNULL(n, "neighbor still exists");
    ASSERT_EQ(n->state, RSVP_NBOR_UP, "state transitions to UP on first REQUEST");
    ASSERT_EQ(n->dst_instance, 0xABCD1234u, "dst_instance updated from rx src_instance");

    rsvp_hello_shutdown();
}

static void test_recv_request_sends_ack(void) {
    TEST_BEGIN("recv_request_sends_ack");
    rsvp_hello_init();
    mock_reset();

    struct in_addr nbr   = ip("10.0.0.5");
    struct in_addr local = ip("10.0.0.1");
    rsvp_hello_add_neighbor(&nbr, &local, 4);

    int before = mock_pkt_count;
    rsvp_hello_recv(&nbr, 0x11111111, 0, RSVP_HELLO_CTYPE_REQUEST);
    ASSERT_GT(mock_pkt_count, before, "receiving REQUEST triggers ACK send");

    rsvp_hello_shutdown();
}

static void test_recv_ack_transitions_to_up(void) {
    TEST_BEGIN("recv_ack_transitions_to_up");
    rsvp_hello_init();
    mock_reset();

    struct in_addr nbr   = ip("10.0.0.6");
    struct in_addr local = ip("10.0.0.1");
    struct rsvp_neighbor* n = rsvp_hello_add_neighbor(&nbr, &local, 5);

    /* Simulate the neighbor ACKing our Hello (its src_instance echoes our src) */
    rsvp_hello_recv(&nbr, 0xDEAD0001, n->src_instance, RSVP_HELLO_CTYPE_ACK);

    n = rsvp_hello_find_neighbor(&nbr);
    ASSERT_EQ(n->state, RSVP_NBOR_UP, "state transitions to UP on first ACK");

    rsvp_hello_shutdown();
}

static void test_recv_increments_hellos_rcvd(void) {
    TEST_BEGIN("recv_increments_hellos_rcvd");
    rsvp_hello_init();
    mock_reset();

    struct in_addr nbr   = ip("10.0.0.7");
    struct in_addr local = ip("10.0.0.1");
    rsvp_hello_add_neighbor(&nbr, &local, 6);

    rsvp_hello_recv(&nbr, 0x12340001, 0, RSVP_HELLO_CTYPE_REQUEST);
    rsvp_hello_recv(&nbr, 0x12340001, 0, RSVP_HELLO_CTYPE_REQUEST);

    struct rsvp_neighbor* n = rsvp_hello_find_neighbor(&nbr);
    ASSERT_GE(n->hellos_rcvd, 2u, "hellos_rcvd incremented for each received Hello");

    rsvp_hello_shutdown();
}

static void test_restart_detection_triggers_frr(void) {
    TEST_BEGIN("restart_detection_triggers_frr");
    rsvp_hello_init();
    mock_reset();
    g_frr_trigger_calls = 0;

    struct in_addr nbr   = ip("10.0.0.8");
    struct in_addr local = ip("10.0.0.1");
    rsvp_hello_add_neighbor(&nbr, &local, 7);

    /* First hello — establishes dst_instance = 0x11111111 */
    rsvp_hello_recv(&nbr, 0x11111111, 0, RSVP_HELLO_CTYPE_REQUEST);
    int frr_before = g_frr_trigger_calls;

    /* Second hello with a CHANGED src_instance — signals neighbor restart */
    rsvp_hello_recv(&nbr, 0x22222222, 0, RSVP_HELLO_CTYPE_REQUEST);
    ASSERT_GT(g_frr_trigger_calls, frr_before,
              "changed src_instance triggers rsvp_frr_trigger() for restart");

    rsvp_hello_shutdown();
}

static void test_autocreate_on_unknown_src(void) {
    TEST_BEGIN("autocreate_on_unknown_src");
    rsvp_hello_init();
    mock_reset();

    /* Receive a Hello from an IP we never explicitly added */
    struct in_addr unknown = ip("10.10.10.10");
    rsvp_hello_recv(&unknown, 0xCAFEBABE, 0, RSVP_HELLO_CTYPE_REQUEST);

    struct rsvp_neighbor* n = rsvp_hello_find_neighbor(&unknown);
    ASSERT_NOTNULL(n, "unknown-source Hello auto-creates a neighbor entry");

    rsvp_hello_shutdown();
}

static void test_src_instance_nonzero_after_add(void) {
    TEST_BEGIN("src_instance_nonzero_after_add");
    rsvp_hello_init();

    struct in_addr nbr   = ip("10.0.0.9");
    struct in_addr local = ip("10.0.0.1");
    struct rsvp_neighbor* n = rsvp_hello_add_neighbor(&nbr, &local, 8);

    ASSERT_NE(n->src_instance, 0u, "src_instance initialized to non-zero value");

    rsvp_hello_shutdown();
}

/* ---------- main --------------------------------------------------------- */

int main(void) {
    printf("=== test_hello ===\n");

    test_add_neighbor_creates_entry();
    test_add_neighbor_idempotent();
    test_find_returns_null_for_unknown();
    test_recv_request_transitions_to_up();
    test_recv_request_sends_ack();
    test_recv_ack_transitions_to_up();
    test_recv_increments_hellos_rcvd();
    test_restart_detection_triggers_frr();
    test_autocreate_on_unknown_src();
    test_src_instance_nonzero_after_add();

    TEST_SUMMARY();
}
