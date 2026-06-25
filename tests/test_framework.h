/**
 * @file test_framework.h
 * @brief Minimal test assertion framework for RSVP-TE unit tests.
 *
 * Each test file defines its own main() that calls individual test functions.
 * Use ASSERT/ASSERT_EQ etc. inside test functions, then call TEST_SUMMARY()
 * at the end of main() to print results and return the right exit code.
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>

static int g_pass = 0;
static int g_fail = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL  %-55s  [%s:%d]\n", (msg), __FILE__, __LINE__); \
        g_fail++; \
    } else { \
        printf("  pass  %s\n", (msg)); \
        g_pass++; \
    } \
} while (0)

#define ASSERT_EQ(a, b, msg)   ASSERT((a) == (b), msg)
#define ASSERT_NE(a, b, msg)   ASSERT((a) != (b), msg)
#define ASSERT_NULL(p, msg)    ASSERT((p) == NULL, msg)
#define ASSERT_NOTNULL(p, msg) ASSERT((p) != NULL, msg)
#define ASSERT_GT(a, b, msg)   ASSERT((a) >  (b), msg)
#define ASSERT_GE(a, b, msg)   ASSERT((a) >= (b), msg)
#define ASSERT_STR_EQ(a, b, msg) ASSERT(strcmp((a), (b)) == 0, msg)

#define TEST_BEGIN(name) printf("\n[%s]\n", (name))

#define TEST_SUMMARY() do { \
    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail); \
    return (g_fail > 0) ? 1 : 0; \
} while (0)

#endif /* TEST_FRAMEWORK_H */
