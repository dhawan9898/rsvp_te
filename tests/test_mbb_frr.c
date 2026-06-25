/**
 * @file test_mbb_frr.c
 * @brief Functional tests for Make-Before-Break (RFC 3209 §6.6) and FRR
 *        (RFC 4090) — bypass association, trigger, revert, and MBB lifecycle.
 */

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdbool.h>

#include "test_framework.h"
#include "common/rsvp_protocol.h"
#include "common/rsvp_error.h"
#include "common/rsvp_log.h"
#include "pi/rsvp_builder.h"
#include "pi/rsvp_parser.h"
#include "pi/rsvp_state_db.h"
#include "pi/rsvp_state_machine.h"
#include "pi/label_mgr.h"
#include "mocks.h"

/* ---------- helpers ------------------------------------------------------ */

static struct in_addr ia(const char* s) {
    struct in_addr a; inet_aton(s, &a); return a;
}

static int parse_rsvp(const uint8_t* rsvp, size_t rsvp_len,
                       struct in_addr src, struct in_addr dst,
                       struct rsvp_message_info* info) {
    static uint8_t pkt[2048];
    struct iphdr* ip = (struct iphdr*)pkt;
    memset(ip, 0, sizeof(*ip));
    ip->ihl = 5; ip->version = 4; ip->protocol = 46;
    ip->saddr = src.s_addr; ip->daddr = dst.s_addr;
    memcpy(pkt + sizeof(*ip), rsvp, rsvp_len);
    memset(info, 0, sizeof(*info));
    return rsvp_parse_packet(pkt, sizeof(*ip) + rsvp_len, info);
}

static size_t build_path(uint8_t* buf, size_t bufsz,
                          struct in_addr src, struct in_addr dst,
                          uint16_t tunnel_id, uint16_t lsp_id) {
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, bufsz, RSVP_MSG_PATH);
    rsvp_builder_add_session_ipv4(&b, &dst, tunnel_id, &dst);
    struct rsvp_sender_ipv4 snd;
    memset(&snd, 0, sizeof(snd));
    snd.source_addr = src;
    snd.lsp_id      = htons(lsp_id);
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &snd, sizeof(snd));
    rsvp_builder_add_hop_ipv4(&b, &src, 1);
    rsvp_builder_add_label_request(&b, 0x0800);
    return rsvp_builder_finalize(&b);
}

static size_t build_resv(uint8_t* buf, size_t bufsz,
                          struct in_addr nhop, struct in_addr dst,
                          uint16_t tunnel_id, uint16_t lsp_id, uint32_t label) {
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, bufsz, RSVP_MSG_RESV);
    rsvp_builder_add_session_ipv4(&b, &dst, tunnel_id, &dst);
    rsvp_builder_add_hop_ipv4(&b, &nhop, 2);
    rsvp_builder_add_style(&b, RSVP_STYLE_FF);
    struct rsvp_sender_ipv4 snd;
    memset(&snd, 0, sizeof(snd));
    snd.source_addr = dst;
    snd.lsp_id      = htons(lsp_id);
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7, &snd, sizeof(snd));
    rsvp_builder_add_label_ipv4(&b, label);
    return rsvp_builder_finalize(&b);
}

/* ---------- MBB tests ---------------------------------------------------- */

static void test_mbb_start_missing_old_psb(void) {
    TEST_BEGIN("mbb_start: missing old PSB returns ERR_NOT_FOUND");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    rsvp_error_t rc = rsvp_mbb_start(200, 1, 2, NULL, 0);
    ASSERT_EQ(rc, RSVP_ERR_NOT_FOUND, "mbb_start returns ERR_NOT_FOUND when old PSB absent");

    rsvp_state_db_cleanup();
}

static void test_mbb_start_non_ingress_psb_rejected(void) {
    TEST_BEGIN("mbb_start: non-ingress PSB rejected");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();
    mock_is_local = false;

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.5");
    uint8_t pbuf[256];
    size_t plen = build_path(pbuf, sizeof(pbuf), src, dst, 201, 1);
    struct rsvp_message_info info;
    parse_rsvp(pbuf, plen, src, dst, &info);
    rsvp_handle_message(&info); /* creates transit PSB (is_ingress = false) */

    rsvp_error_t rc = rsvp_mbb_start(201, 1, 2, NULL, 0);
    ASSERT_EQ(rc, RSVP_ERR_INVALID_PARAM,
              "mbb_start returns ERR_INVALID_PARAM for transit PSB");

    rsvp_state_db_cleanup();
}

static void test_mbb_start_creates_new_psb(void) {
    TEST_BEGIN("mbb_start: creates new PSB with new LSP-ID");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.9");
    rsvp_initiate_path(&src, &dst, 202, "mbb_test");

    /* Old PSB is for LSPID=1; create new one with LSPID=2 */
    rsvp_error_t rc = rsvp_mbb_start(202, 1, 2, NULL, 0);
    ASSERT_EQ(rc, RSVP_SUCCESS, "mbb_start returns SUCCESS");

    struct rsvp_psb* new_psb = rsvp_psb_find_by_id(202, 2);
    ASSERT_NOTNULL(new_psb, "new PSB (LSPID=2) exists after mbb_start");
    ASSERT(new_psb->is_mbb_pending, "new PSB has is_mbb_pending = true");
    ASSERT_EQ(new_psb->mbb_old_lsp_id, 1u, "mbb_old_lsp_id = old LSPID");

    rsvp_state_db_cleanup();
}

static void test_mbb_start_old_psb_still_active(void) {
    TEST_BEGIN("mbb_start: old PSB remains active");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.9");
    rsvp_initiate_path(&src, &dst, 203, "mbb_old_active");
    rsvp_mbb_start(203, 1, 2, NULL, 0);

    ASSERT_NOTNULL(rsvp_psb_find_by_id(203, 1),
                   "incumbent PSB (LSPID=1) still exists after mbb_start");
    ASSERT_NOTNULL(rsvp_psb_find_by_id(203, 2),
                   "new PSB (LSPID=2) also exists");

    rsvp_state_db_cleanup();
}

static void test_mbb_start_duplicate_new_lsp_id(void) {
    TEST_BEGIN("mbb_start: duplicate new LSPID returns ERR_ALREADY_EXISTS");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.9");
    rsvp_initiate_path(&src, &dst, 204, "mbb_dup");
    rsvp_mbb_start(204, 1, 2, NULL, 0); /* creates LSPID=2 */

    rsvp_error_t rc = rsvp_mbb_start(204, 1, 2, NULL, 0); /* same new LSPID again */
    ASSERT_EQ(rc, RSVP_ERR_ALREADY_EXISTS,
              "second mbb_start with same new LSPID returns ERR_ALREADY_EXISTS");

    rsvp_state_db_cleanup();
}

static void test_mbb_complete_on_first_resv(void) {
    TEST_BEGIN("mbb_complete: old PSB torn down when new RESV arrives");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.9");
    rsvp_initiate_path(&src, &dst, 205, "mbb_complete");
    rsvp_mbb_start(205, 1, 2, NULL, 0);

    ASSERT_NOTNULL(rsvp_psb_find_by_id(205, 1), "old PSB (LSPID=1) exists before RESV");
    ASSERT_NOTNULL(rsvp_psb_find_by_id(205, 2), "new PSB (LSPID=2) exists before RESV");

    /* Simulate RESV arriving for the NEW path (LSPID=2) */
    uint8_t rbuf[256];
    size_t rlen = build_resv(rbuf, sizeof(rbuf), dst, src, 205, 2, 9000);
    struct rsvp_message_info rinfo;
    parse_rsvp(rbuf, rlen, dst, src, &rinfo);
    rsvp_handle_message(&rinfo);

    /* Old PSB should now be gone */
    ASSERT_NULL(rsvp_psb_find_by_id(205, 1),
                "old PSB (LSPID=1) torn down after new RESV installed");
    /* New PSB may or may not still be present depending on whether it's the ingress RSB */
    /* We care only that the OLD path is torn down — verified above */

    rsvp_state_db_cleanup();
}

/* ---------- FRR tests ---------------------------------------------------- */

static void test_frr_revert_no_active_frr_no_crash(void) {
    TEST_BEGIN("frr_revert: no active FRR — no crash");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    /* Should not crash when no LSPs are currently FRR-switched */
    rsvp_frr_revert(5);
    ASSERT(true, "frr_revert with no active FRR does not crash");

    rsvp_state_db_cleanup();
}

static void test_frr_enable_protection_missing_psb(void) {
    TEST_BEGIN("frr_enable_protection: missing PSB returns ERR_NOT_FOUND");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    rsvp_error_t rc = rsvp_frr_enable_protection(999, 1, RSVP_FRR_FACILITY, 888);
    ASSERT_EQ(rc, RSVP_ERR_NOT_FOUND, "missing PSB returns ERR_NOT_FOUND");

    rsvp_state_db_cleanup();
}

static void test_frr_dump_no_crash(void) {
    TEST_BEGIN("frr_dump: no crash on empty state");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    rsvp_frr_dump(); /* smoke test — must not crash */
    ASSERT(true, "frr_dump with no LSPs does not crash");

    rsvp_state_db_cleanup();
}

static void test_frr_trigger_no_active_lsps_no_crash(void) {
    TEST_BEGIN("frr_trigger: no matching LSPs — no crash");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    rsvp_frr_trigger(5); /* interface 5 has no protected LSPs */
    ASSERT(true, "frr_trigger with no matching LSPs does not crash");

    rsvp_state_db_cleanup();
}

static void test_frr_enable_protection_without_bypass_rsb(void) {
    TEST_BEGIN("frr_enable_protection: bypass tunnel with no RESV returns ERR_FRR_NOT_CONFIGURED");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.5");

    /* Create the primary LSP */
    rsvp_initiate_path(&src, &dst, 300, "primary");

    /* Create a bypass tunnel PSB directly in the DB */
    struct rsvp_path_key byp_key;
    memset(&byp_key, 0, sizeof(byp_key));
    byp_key.session.dest_addr  = ia("10.0.0.6");
    byp_key.session.tunnel_id  = htons(301);
    byp_key.sender.source_addr = src;
    byp_key.sender.lsp_id      = htons(1);
    struct rsvp_psb* byp = rsvp_psb_create(&byp_key);
    byp->is_bypass_tunnel = true;

    /* No RSB for bypass — should fail */
    rsvp_error_t rc = rsvp_frr_enable_protection(300, 1, RSVP_FRR_FACILITY, 301);
    ASSERT_EQ(rc, RSVP_ERR_FRR_NOT_CONFIGURED,
              "bypass without RSB returns ERR_FRR_NOT_CONFIGURED");

    rsvp_state_db_cleanup();
}

/* ---------- main --------------------------------------------------------- */

int main(void) {
    rsvp_log_init("tests/test_mbb_frr.log");
    rsvp_set_log_level(LOG_LEVEL_WARN);
    printf("=== test_mbb_frr ===\n");

    test_mbb_start_missing_old_psb();
    test_mbb_start_non_ingress_psb_rejected();
    test_mbb_start_creates_new_psb();
    test_mbb_start_old_psb_still_active();
    test_mbb_start_duplicate_new_lsp_id();
    test_mbb_complete_on_first_resv();
    test_frr_revert_no_active_frr_no_crash();
    test_frr_enable_protection_missing_psb();
    test_frr_dump_no_crash();
    test_frr_trigger_no_active_lsps_no_crash();
    test_frr_enable_protection_without_bypass_rsb();

    TEST_SUMMARY();
}
