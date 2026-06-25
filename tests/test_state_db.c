/**
 * @file test_state_db.c
 * @brief Unit tests for rsvp_state_db — PSB/RSB/BSB hash-table CRUD.
 *
 * Tests cover: create, find-by-key, find-by-id, delete, hash collisions,
 * and bucket iteration used by the FRR trigger and shutdown paths.
 */

#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "test_framework.h"
#include "common/rsvp_protocol.h"
#include "pi/rsvp_state.h"
#include "pi/rsvp_state_db.h"

/* ---------- helpers ------------------------------------------------------ */

static struct rsvp_path_key make_key(const char* dest_ip, uint16_t tunnel_id,
                                      const char* src_ip,  uint16_t lsp_id) {
    struct rsvp_path_key k;
    memset(&k, 0, sizeof(k));
    inet_aton(dest_ip, &k.session.dest_addr);
    k.session.tunnel_id = htons(tunnel_id);
    inet_aton(src_ip, &k.sender.source_addr);
    k.sender.lsp_id = htons(lsp_id);
    return k;
}

/* ---------- PSB tests ---------------------------------------------------- */

static void test_psb_create_and_find(void) {
    TEST_BEGIN("psb_create_and_find");
    rsvp_state_db_init();

    struct rsvp_path_key k = make_key("10.0.0.2", 10, "10.0.0.1", 1);
    struct rsvp_psb* psb = rsvp_psb_create(&k);
    ASSERT_NOTNULL(psb, "create returns non-NULL PSB");

    struct rsvp_psb* found = rsvp_psb_find(&k);
    ASSERT_NOTNULL(found, "find returns non-NULL after create");
    ASSERT_EQ(found, psb, "find returns same pointer");
    ASSERT_EQ(ntohs(found->key.session.tunnel_id), 10u, "tunnel_id preserved in PSB key");

    rsvp_state_db_cleanup();
}

static void test_psb_find_nonexistent(void) {
    TEST_BEGIN("psb_find_nonexistent");
    rsvp_state_db_init();

    struct rsvp_path_key k = make_key("10.0.0.3", 99, "10.0.0.1", 1);
    struct rsvp_psb* found = rsvp_psb_find(&k);
    ASSERT_NULL(found, "find returns NULL for unknown key");

    rsvp_state_db_cleanup();
}

static void test_psb_delete(void) {
    TEST_BEGIN("psb_delete");
    rsvp_state_db_init();

    struct rsvp_path_key k = make_key("10.0.0.4", 20, "10.0.0.1", 2);
    rsvp_psb_create(&k);
    struct rsvp_psb* psb = rsvp_psb_find(&k);
    ASSERT_NOTNULL(psb, "PSB exists before delete");

    rsvp_psb_delete(psb);
    ASSERT_NULL(rsvp_psb_find(&k), "PSB is gone after delete");

    rsvp_state_db_cleanup();
}

static void test_psb_find_by_id(void) {
    TEST_BEGIN("psb_find_by_id");
    rsvp_state_db_init();

    struct rsvp_path_key k = make_key("10.0.0.5", 30, "10.0.0.1", 5);
    rsvp_psb_create(&k);

    struct rsvp_psb* found = rsvp_psb_find_by_id(30, 5);
    ASSERT_NOTNULL(found, "find_by_id returns entry");
    ASSERT_EQ(ntohs(found->key.sender.lsp_id), 5u, "lsp_id matches");

    /* Non-existent combination */
    ASSERT_NULL(rsvp_psb_find_by_id(30, 999), "find_by_id returns NULL for unknown ids");
    ASSERT_NULL(rsvp_psb_find_by_id(777, 5),  "find_by_id returns NULL for unknown tunnel");

    rsvp_state_db_cleanup();
}

static void test_psb_multiple_entries(void) {
    TEST_BEGIN("psb_multiple_entries");
    rsvp_state_db_init();

    struct rsvp_path_key k1 = make_key("10.0.0.2", 1, "10.0.0.1", 1);
    struct rsvp_path_key k2 = make_key("10.0.0.2", 2, "10.0.0.1", 1);
    struct rsvp_path_key k3 = make_key("10.0.0.2", 3, "10.0.0.1", 1);

    rsvp_psb_create(&k1);
    rsvp_psb_create(&k2);
    rsvp_psb_create(&k3);

    ASSERT_NOTNULL(rsvp_psb_find(&k1), "PSB 1 found");
    ASSERT_NOTNULL(rsvp_psb_find(&k2), "PSB 2 found");
    ASSERT_NOTNULL(rsvp_psb_find(&k3), "PSB 3 found");

    rsvp_psb_delete(rsvp_psb_find(&k2));
    ASSERT_NOTNULL(rsvp_psb_find(&k1), "PSB 1 still present after deleting PSB 2");
    ASSERT_NULL(rsvp_psb_find(&k2),    "PSB 2 gone");
    ASSERT_NOTNULL(rsvp_psb_find(&k3), "PSB 3 still present after deleting PSB 2");

    rsvp_state_db_cleanup();
}

static void test_psb_bucket_iterator(void) {
    TEST_BEGIN("psb_bucket_iterator");
    rsvp_state_db_init();

    /* Insert several PSBs and count them via bucket walk */
    struct rsvp_path_key keys[5];
    for (int i = 0; i < 5; i++) {
        char dest[32];
        snprintf(dest, sizeof(dest), "10.0.%d.2", i);
        keys[i] = make_key(dest, (uint16_t)(100 + i), "10.0.0.1", (uint16_t)(i + 1));
        rsvp_psb_create(&keys[i]);
    }

    int count = 0;
    for (int bkt = 0; bkt < 1024; bkt++) {
        for (struct rsvp_psb* p = rsvp_psb_find_by_bucket(bkt); p; p = p->next_hash)
            count++;
    }
    ASSERT_EQ(count, 5, "bucket iterator visits all 5 PSBs");

    rsvp_state_db_cleanup();
}

/* ---------- RSB tests ---------------------------------------------------- */

static void test_rsb_create_find_delete(void) {
    TEST_BEGIN("rsb_create_find_delete");
    rsvp_state_db_init();

    struct rsvp_path_key k = make_key("10.0.0.2", 50, "10.0.0.1", 1);
    struct rsvp_rsb* rsb = rsvp_rsb_create(&k);
    ASSERT_NOTNULL(rsb, "RSB create returns non-NULL");

    ASSERT_NOTNULL(rsvp_rsb_find(&k), "RSB found after create");

    rsvp_rsb_delete(rsb);
    ASSERT_NULL(rsvp_rsb_find(&k), "RSB gone after delete");

    rsvp_state_db_cleanup();
}

static void test_rsb_find_nonexistent(void) {
    TEST_BEGIN("rsb_find_nonexistent");
    rsvp_state_db_init();

    struct rsvp_path_key k = make_key("10.0.0.6", 60, "10.0.0.1", 7);
    ASSERT_NULL(rsvp_rsb_find(&k), "RSB find returns NULL for unknown key");

    rsvp_state_db_cleanup();
}

/* ---------- BSB tests ---------------------------------------------------- */

static void test_bsb_create_find_delete(void) {
    TEST_BEGIN("bsb_create_find_delete");
    rsvp_state_db_init();

    struct rsvp_path_key k = make_key("10.0.0.7", 70, "10.0.0.1", 3);
    struct rsvp_bsb* bsb = rsvp_bsb_create(&k);
    ASSERT_NOTNULL(bsb, "BSB create returns non-NULL");

    ASSERT_NOTNULL(rsvp_bsb_find(&k), "BSB found after create");

    rsvp_bsb_delete(bsb);
    ASSERT_NULL(rsvp_bsb_find(&k), "BSB gone after delete");

    rsvp_state_db_cleanup();
}

/* ---------- main --------------------------------------------------------- */

int main(void) {
    printf("=== test_state_db ===\n");

    test_psb_create_and_find();
    test_psb_find_nonexistent();
    test_psb_delete();
    test_psb_find_by_id();
    test_psb_multiple_entries();
    test_psb_bucket_iterator();
    test_rsb_create_find_delete();
    test_rsb_find_nonexistent();
    test_bsb_create_find_delete();

    TEST_SUMMARY();
}
