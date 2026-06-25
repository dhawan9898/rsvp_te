/**
 * @file test_label_mgr.c
 * @brief Unit tests for label_mgr — MPLS label pool allocator.
 */

#include <stdint.h>
#include <stdbool.h>

#include "test_framework.h"
#include "pi/label_mgr.h"

static void test_alloc_returns_value_in_range(void) {
    TEST_BEGIN("alloc_returns_value_in_range");
    label_mgr_init(1000, 2000);

    uint32_t label = label_mgr_alloc();
    ASSERT_GE(label, 1000u, "allocated label >= min");
    ASSERT(label <= 2000u, "allocated label <= max");
}

static void test_alloc_sequential_unique(void) {
    TEST_BEGIN("alloc_sequential_unique");
    label_mgr_init(100, 200);

    uint32_t a = label_mgr_alloc();
    uint32_t b = label_mgr_alloc();
    ASSERT_NE(a, 0u, "first allocation non-zero");
    ASSERT_NE(b, 0u, "second allocation non-zero");
    ASSERT_NE(a, b,  "two consecutive allocations give different labels");
}

static void test_free_and_realloc(void) {
    TEST_BEGIN("free_and_realloc");
    label_mgr_init(500, 600);

    uint32_t first  = label_mgr_alloc();
    uint32_t second = label_mgr_alloc();
    ASSERT_NE(first,  0u, "first alloc non-zero");
    ASSERT_NE(second, 0u, "second alloc non-zero");

    label_mgr_free(first);
    /* After freeing, the pool must be able to allocate again */
    uint32_t reused = label_mgr_alloc();
    ASSERT_NE(reused, 0u, "alloc after free succeeds");
    (void)second;
}

static void test_pool_exhaustion_returns_zero(void) {
    TEST_BEGIN("pool_exhaustion_returns_zero");
    /* Tiny pool: only 3 labels */
    label_mgr_init(10, 12);

    uint32_t l1 = label_mgr_alloc();
    uint32_t l2 = label_mgr_alloc();
    uint32_t l3 = label_mgr_alloc();
    ASSERT_NE(l1, 0u, "1st alloc ok");
    ASSERT_NE(l2, 0u, "2nd alloc ok");
    ASSERT_NE(l3, 0u, "3rd alloc ok");

    /* Pool should be exhausted now */
    uint32_t overflow = label_mgr_alloc();
    ASSERT_EQ(overflow, 0u, "4th alloc returns 0 (pool exhausted)");
}

static void test_free_does_not_crash_on_out_of_range(void) {
    TEST_BEGIN("free_does_not_crash_on_out_of_range");
    label_mgr_init(1000, 2000);
    /* Free a label outside the pool range — should not crash or corrupt state */
    label_mgr_free(0);
    label_mgr_free(9999);
    uint32_t l = label_mgr_alloc();
    ASSERT_NE(l, 0u, "alloc still works after invalid frees");
}

static void test_reinit_resets_pool(void) {
    TEST_BEGIN("reinit_resets_pool");
    label_mgr_init(1, 3);
    label_mgr_alloc(); /* 1 */
    label_mgr_alloc(); /* 2 */
    label_mgr_alloc(); /* 3 — exhausted */
    ASSERT_EQ(label_mgr_alloc(), 0u, "pool exhausted before reinit");

    label_mgr_init(1, 3); /* reinitialize */
    ASSERT_NE(label_mgr_alloc(), 0u, "alloc works again after reinit");
}

/* ---------- main --------------------------------------------------------- */

int main(void) {
    printf("=== test_label_mgr ===\n");

    test_alloc_returns_value_in_range();
    test_alloc_sequential_unique();
    test_free_and_realloc();
    test_pool_exhaustion_returns_zero();
    test_free_does_not_crash_on_out_of_range();
    test_reinit_resets_pool();

    TEST_SUMMARY();
}
