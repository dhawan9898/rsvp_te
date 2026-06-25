/**
 * @file test_if.c
 * @brief Unit tests for rsvp_if — per-interface RSVP state management.
 *
 * Tests cover: enable/disable, bandwidth configuration, per-priority
 * reservation accounting, and available-bandwidth calculation.
 */

#include <string.h>
#include <stdbool.h>
#include <math.h>

#include "test_framework.h"
#include "pi/rsvp_if.h"

static void test_enable_creates_entry(void) {
    TEST_BEGIN("enable_creates_entry");
    rsvp_if_init();

    struct rsvp_if* iface = rsvp_if_enable("eth0");
    ASSERT_NOTNULL(iface, "enable returns non-NULL entry");
    ASSERT(iface->rsvp_enabled, "rsvp_enabled = true after enable");
    ASSERT_STR_EQ(iface->name, "eth0", "name stored correctly");

    rsvp_if_shutdown();
}

static void test_enable_idempotent(void) {
    TEST_BEGIN("enable_idempotent");
    rsvp_if_init();

    struct rsvp_if* a = rsvp_if_enable("eth1");
    struct rsvp_if* b = rsvp_if_enable("eth1");
    ASSERT_EQ(a, b, "second enable returns same pointer");

    rsvp_if_shutdown();
}

static void test_disable_clears_flag(void) {
    TEST_BEGIN("disable_clears_flag");
    rsvp_if_init();

    rsvp_if_enable("eth2");
    rsvp_if_disable("eth2");

    struct rsvp_if* iface = rsvp_if_get_by_name("eth2");
    ASSERT_NOTNULL(iface, "entry still exists after disable");
    ASSERT(!iface->rsvp_enabled, "rsvp_enabled = false after disable");

    rsvp_if_shutdown();
}

static void test_get_by_name_nonexistent(void) {
    TEST_BEGIN("get_by_name_nonexistent");
    rsvp_if_init();

    struct rsvp_if* iface = rsvp_if_get_by_name("nonexistent0");
    ASSERT_NULL(iface, "get_by_name returns NULL for unknown interface");

    rsvp_if_shutdown();
}

static void test_set_bandwidth_stored(void) {
    TEST_BEGIN("set_bandwidth_stored");
    rsvp_if_init();

    rsvp_if_enable("eth3");
    rsvp_if_set_bandwidth("eth3", 1e9, 800e6);

    struct rsvp_if* iface = rsvp_if_get_by_name("eth3");
    ASSERT_NOTNULL(iface, "entry found after set_bandwidth");
    ASSERT(iface->total_bw == 1e9, "total_bw = 1 Gbps");
    ASSERT(iface->reservable_bw == 800e6, "reservable_bw = 800 Mbps");

    rsvp_if_shutdown();
}

static void test_reserve_increases_reserved(void) {
    TEST_BEGIN("reserve_increases_reserved");
    rsvp_if_init();

    struct rsvp_if* iface = rsvp_if_enable("eth4");
    iface->ifindex = 10;
    rsvp_if_set_bandwidth("eth4", 1e9, 1e9);

    rsvp_if_reserve_bw(10, 0, 100e6);
    ASSERT(iface->reserved_bw[0] == 100e6, "reserved_bw[0] = 100 Mbps after reserve");

    rsvp_if_reserve_bw(10, 0, 50e6);
    ASSERT(iface->reserved_bw[0] == 150e6, "reserved_bw[0] = 150 Mbps after second reserve");

    rsvp_if_shutdown();
}

static void test_release_decreases_reserved(void) {
    TEST_BEGIN("release_decreases_reserved");
    rsvp_if_init();

    struct rsvp_if* iface = rsvp_if_enable("eth5");
    iface->ifindex = 11;
    rsvp_if_set_bandwidth("eth5", 1e9, 1e9);

    rsvp_if_reserve_bw(11, 1, 200e6);
    rsvp_if_release_bw(11, 1, 200e6);
    ASSERT(iface->reserved_bw[1] == 0.0, "reserved_bw[1] = 0 after release");

    rsvp_if_shutdown();
}

static void test_available_bw_unreserved(void) {
    TEST_BEGIN("available_bw_unreserved");
    rsvp_if_init();

    struct rsvp_if* iface = rsvp_if_enable("eth6");
    iface->ifindex = 12;
    rsvp_if_set_bandwidth("eth6", 1e9, 1e9);

    double avail = rsvp_if_available_bw(12, 7);
    ASSERT(avail == 1e9, "available_bw = full reservable when nothing reserved");

    rsvp_if_shutdown();
}

static void test_available_bw_after_reservation(void) {
    TEST_BEGIN("available_bw_after_reservation");
    rsvp_if_init();

    struct rsvp_if* iface = rsvp_if_enable("eth7");
    iface->ifindex = 13;
    rsvp_if_set_bandwidth("eth7", 1e9, 1e9);

    rsvp_if_reserve_bw(13, 0, 300e6);  /* priority 0 */
    rsvp_if_reserve_bw(13, 4, 100e6);  /* priority 4 */

    /* available_bw at priority 7 = reservable - sum of all priorities 0..7 */
    double avail = rsvp_if_available_bw(13, 7);
    ASSERT(avail == 600e6, "available_bw = 600 Mbps after 400 Mbps reserved");

    rsvp_if_shutdown();
}

static void test_table_full_returns_null(void) {
    TEST_BEGIN("table_full_returns_null");
    rsvp_if_init();

    /* Fill the table */
    for (int i = 0; i < RSVP_MAX_IF; i++) {
        char name[16];
        snprintf(name, sizeof(name), "eth%d", i);
        rsvp_if_enable(name);
    }
    /* One more should fail */
    struct rsvp_if* overflow = rsvp_if_enable("overflow0");
    ASSERT_NULL(overflow, "enable returns NULL when table is full");

    rsvp_if_shutdown();
}

static void test_disable_nonexistent_no_crash(void) {
    TEST_BEGIN("disable_nonexistent_no_crash");
    rsvp_if_init();
    /* Should not crash on unknown interface */
    rsvp_if_disable("ghost0");
    ASSERT(true, "disable of unknown interface does not crash");
    rsvp_if_shutdown();
}

/* ---------- main --------------------------------------------------------- */

int main(void) {
    printf("=== test_if ===\n");

    test_enable_creates_entry();
    test_enable_idempotent();
    test_disable_clears_flag();
    test_get_by_name_nonexistent();
    test_set_bandwidth_stored();
    test_reserve_increases_reserved();
    test_release_decreases_reserved();
    test_available_bw_unreserved();
    test_available_bw_after_reservation();
    test_table_full_returns_null();
    test_disable_nonexistent_no_crash();

    TEST_SUMMARY();
}
