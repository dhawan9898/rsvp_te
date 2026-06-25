/**
 * @file test_state_machine.c
 * @brief Functional tests for rsvp_state_machine — full PATH/RESV/Tear flow.
 *
 * Each test drives the state machine through a specific scenario using
 * rsvp_handle_message() and verifies the resulting state and side effects
 * (PSB/RSB creation, MPLS installs, forwarded packets).
 *
 * The mock functions in mocks.c replace all HAL and dispatcher symbols so
 * this test runs without Linux-specific netlink/timerfd code.
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

/* Wrap a raw RSVP buffer in a fake IP header and parse it into info */
static int parse_rsvp(const uint8_t* rsvp, size_t rsvp_len,
                       struct in_addr src, struct in_addr dst,
                       struct rsvp_message_info* info) {
    static uint8_t pkt[2048];
    struct iphdr* ip = (struct iphdr*)pkt;
    memset(ip, 0, sizeof(*ip));
    ip->ihl      = 5;
    ip->version  = 4;
    ip->protocol = 46;
    ip->saddr    = src.s_addr;
    ip->daddr    = dst.s_addr;
    memcpy(pkt + sizeof(*ip), rsvp, rsvp_len);
    memset(info, 0, sizeof(*info));
    return rsvp_parse_packet(pkt, sizeof(*ip) + rsvp_len, info);
}

/* Build a PATH and return its length */
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

/* Build a RESV and return its length */
static size_t build_resv(uint8_t* buf, size_t bufsz,
                          struct in_addr src, struct in_addr dst,
                          uint16_t tunnel_id, uint16_t lsp_id,
                          uint32_t label_out) {
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, bufsz, RSVP_MSG_RESV);
    rsvp_builder_add_session_ipv4(&b, &dst, tunnel_id, &dst);
    rsvp_builder_add_hop_ipv4(&b, &src, 2);
    rsvp_builder_add_style(&b, RSVP_STYLE_FF);
    struct rsvp_sender_ipv4 snd;
    memset(&snd, 0, sizeof(snd));
    snd.source_addr = dst;
    snd.lsp_id      = htons(lsp_id);
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7, &snd, sizeof(snd));
    rsvp_builder_add_label_ipv4(&b, label_out);
    return rsvp_builder_finalize(&b);
}

/* ---------- tests -------------------------------------------------------- */

static void test_path_at_egress_creates_psb_and_sends_resv(void) {
    TEST_BEGIN("path_at_egress: creates PSB and sends RESV");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();
    mock_is_local = true; /* this node IS the destination */

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.2");
    uint8_t rsvp[256];
    size_t rsvp_len = build_path(rsvp, sizeof(rsvp), src, dst, 11, 1);

    struct rsvp_message_info info;
    int rc = parse_rsvp(rsvp, rsvp_len, src, dst, &info);
    ASSERT_EQ(rc, RSVP_SUCCESS, "parse succeeds");

    rsvp_handle_message(&info);

    /* A PSB must have been created */
    struct rsvp_path_key key;
    memset(&key, 0, sizeof(key));
    key.session.dest_addr = dst;
    key.session.tunnel_id = htons(11);
    key.sender.source_addr = src;
    key.sender.lsp_id = htons(1);
    ASSERT_NOTNULL(rsvp_psb_find(&key), "PSB created at egress");

    /* A RESV should have been sent upstream */
    ASSERT_GT(mock_pkt_count, 0, "RESV message sent upstream by egress");

    rsvp_state_db_cleanup();
}

static void test_path_at_transit_creates_psb_and_forwards(void) {
    TEST_BEGIN("path_at_transit: creates PSB and forwards PATH");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();
    mock_is_local = false; /* this node is NOT the destination */

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.5");
    uint8_t rsvp[256];
    size_t rsvp_len = build_path(rsvp, sizeof(rsvp), src, dst, 12, 1);

    struct rsvp_message_info info;
    parse_rsvp(rsvp, rsvp_len, src, dst, &info);
    rsvp_handle_message(&info);

    struct rsvp_path_key key;
    memset(&key, 0, sizeof(key));
    key.session.dest_addr = dst;
    key.session.tunnel_id = htons(12);
    key.sender.source_addr = src;
    key.sender.lsp_id = htons(1);
    ASSERT_NOTNULL(rsvp_psb_find(&key), "PSB created at transit");
    ASSERT_GT(mock_pkt_count, 0, "PATH forwarded downstream by transit");

    rsvp_state_db_cleanup();
}

static void test_path_refresh_does_not_duplicate_psb(void) {
    TEST_BEGIN("path_refresh: does not create duplicate PSB");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();
    mock_is_local = false;

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.3");
    uint8_t rsvp[256];
    size_t rsvp_len = build_path(rsvp, sizeof(rsvp), src, dst, 13, 1);

    struct rsvp_message_info info;
    parse_rsvp(rsvp, rsvp_len, src, dst, &info);
    rsvp_handle_message(&info); /* first PATH — creates PSB */

    struct rsvp_message_info info2;
    parse_rsvp(rsvp, rsvp_len, src, dst, &info2);
    rsvp_handle_message(&info2); /* second PATH — refresh only */

    /* Count PSBs for tunnel 13 */
    int count = 0;
    for (int bkt = 0; bkt < 1024; bkt++) {
        for (struct rsvp_psb* p = rsvp_psb_find_by_bucket(bkt); p; p = p->next_hash) {
            if (ntohs(p->key.session.tunnel_id) == 13)
                count++;
        }
    }
    ASSERT_EQ(count, 1, "only one PSB exists for tunnel 13 after two identical PATHs");

    rsvp_state_db_cleanup();
}

static void test_resv_at_ingress_installs_mpls(void) {
    TEST_BEGIN("resv_at_ingress: installs MPLS forwarding entry");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.2");

    /* Step 1: create a PSB via the state machine (ingress node) */
    rsvp_initiate_path(&src, &dst, 14, "test_ingress_resv");

    /* Step 2: find the PSB and build a RESV response for it */
    struct rsvp_psb* psb = rsvp_psb_find_by_id(14, 1);
    ASSERT_NOTNULL(psb, "PSB created by rsvp_initiate_path");

    mock_reset();
    uint8_t rsvp[256];
    size_t rsvp_len = build_resv(rsvp, sizeof(rsvp), dst, src, 14, 1, 5000);

    struct rsvp_message_info info;
    parse_rsvp(rsvp, rsvp_len, dst, src, &info);
    rsvp_handle_message(&info);

    ASSERT_GT(mock_mpls_install_calls, 0, "hal_mpls_install called when RESV arrives at ingress");

    rsvp_state_db_cleanup();
}

static void test_resv_at_transit_allocates_label_and_propagates(void) {
    TEST_BEGIN("resv_at_transit: allocates label and propagates upstream");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();
    mock_is_local = false;

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.5");

    /* First inject PATH so PSB exists */
    uint8_t path_buf[256];
    size_t path_len = build_path(path_buf, sizeof(path_buf), src, dst, 15, 1);
    struct rsvp_message_info path_info;
    parse_rsvp(path_buf, path_len, src, dst, &path_info);
    rsvp_handle_message(&path_info);

    mock_reset();

    /* Now inject a RESV from downstream */
    struct in_addr downstream = ia("10.0.0.4");
    uint8_t resv_buf[256];
    size_t resv_len = build_resv(resv_buf, sizeof(resv_buf), downstream, src, 15, 1, 7000);
    struct rsvp_message_info resv_info;
    parse_rsvp(resv_buf, resv_len, downstream, src, &resv_info);
    rsvp_handle_message(&resv_info);

    ASSERT_GT(mock_mpls_install_calls, 0, "MPLS swap installed at transit");
    ASSERT_GT(mock_pkt_count, 0,          "RESV propagated upstream by transit");

    rsvp_state_db_cleanup();
}

static void test_pathtear_removes_psb(void) {
    TEST_BEGIN("pathtear: removes PSB");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();
    mock_is_local = false;

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.5");

    /* Create PSB via PATH */
    uint8_t path_buf[256];
    size_t path_len = build_path(path_buf, sizeof(path_buf), src, dst, 16, 1);
    struct rsvp_message_info path_info;
    parse_rsvp(path_buf, path_len, src, dst, &path_info);
    rsvp_handle_message(&path_info);

    struct rsvp_path_key key = path_info.key;
    ASSERT_NOTNULL(rsvp_psb_find(&key), "PSB exists before PathTear");

    /* Send PathTear */
    uint8_t tear_buf[256];
    struct rsvp_builder b;
    rsvp_builder_init(&b, tear_buf, sizeof(tear_buf), RSVP_MSG_PATHTEAR);
    rsvp_builder_add_session_ipv4(&b, &dst, 16, &dst);
    rsvp_builder_add_hop_ipv4(&b, &src, 1);
    struct rsvp_sender_ipv4 snd;
    memset(&snd, 0, sizeof(snd));
    snd.source_addr = src;
    snd.lsp_id      = htons(1);
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &snd, sizeof(snd));
    size_t tear_len = rsvp_builder_finalize(&b);

    struct rsvp_message_info tear_info;
    parse_rsvp(tear_buf, tear_len, src, dst, &tear_info);
    rsvp_handle_message(&tear_info);

    ASSERT_NULL(rsvp_psb_find(&key), "PSB removed after PathTear");

    rsvp_state_db_cleanup();
}

static void test_resvtear_removes_rsb(void) {
    TEST_BEGIN("resvtear: removes RSB");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();
    mock_is_local = false;

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.5");

    /* Install PSB and RSB */
    uint8_t path_buf[256];
    size_t path_len = build_path(path_buf, sizeof(path_buf), src, dst, 17, 1);
    struct rsvp_message_info path_info;
    parse_rsvp(path_buf, path_len, src, dst, &path_info);
    rsvp_handle_message(&path_info);

    struct in_addr downstream = ia("10.0.0.4");
    uint8_t resv_buf[256];
    size_t resv_len = build_resv(resv_buf, sizeof(resv_buf), downstream, src, 17, 1, 8000);
    struct rsvp_message_info resv_info;
    parse_rsvp(resv_buf, resv_len, downstream, src, &resv_info);
    rsvp_handle_message(&resv_info);

    ASSERT_NOTNULL(rsvp_rsb_find(&path_info.key), "RSB exists before ResvTear");

    /* Now send ResvTear */
    uint8_t rtear_buf[256];
    struct rsvp_builder b;
    rsvp_builder_init(&b, rtear_buf, sizeof(rtear_buf), RSVP_MSG_RESVTEAR);
    rsvp_builder_add_session_ipv4(&b, &dst, 17, &dst);
    rsvp_builder_add_hop_ipv4(&b, &downstream, 2);
    rsvp_builder_add_style(&b, RSVP_STYLE_FF);
    struct rsvp_sender_ipv4 snd;
    memset(&snd, 0, sizeof(snd));
    snd.source_addr = dst;
    snd.lsp_id      = htons(1);
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7, &snd, sizeof(snd));
    size_t rtear_len = rsvp_builder_finalize(&b);

    struct rsvp_message_info rtear_info;
    parse_rsvp(rtear_buf, rtear_len, downstream, src, &rtear_info);
    rsvp_handle_message(&rtear_info);

    ASSERT_NULL(rsvp_rsb_find(&path_info.key), "RSB removed after ResvTear");
    ASSERT_GT(mock_mpls_remove_calls, 0, "hal_mpls_remove called on ResvTear");

    rsvp_state_db_cleanup();
}

static void test_initiate_path_creates_psb(void) {
    TEST_BEGIN("rsvp_initiate_path: creates PSB and sends PATH");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.9");
    rsvp_initiate_path(&src, &dst, 18, "smoke_test");

    struct rsvp_psb* psb = rsvp_psb_find_by_id(18, 1);
    ASSERT_NOTNULL(psb, "PSB created by rsvp_initiate_path");
    ASSERT(psb->is_ingress, "PSB marked as ingress");
    ASSERT_GT(mock_pkt_count, 0, "PATH message sent by rsvp_initiate_path");

    rsvp_state_db_cleanup();
}

static void test_teardown_path_sends_pathtear(void) {
    TEST_BEGIN("rsvp_teardown_path: sends PathTear");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);
    mock_reset();

    struct in_addr src = ia("10.0.0.1"), dst = ia("10.0.0.9");
    rsvp_initiate_path(&src, &dst, 19, "teardown_test");

    mock_reset();
    rsvp_teardown_path(19, 1);

    ASSERT_GT(mock_pkt_count, 0, "PathTear sent by rsvp_teardown_path");
    ASSERT_NULL(rsvp_psb_find_by_id(19, 1), "PSB cleaned up after teardown");

    rsvp_state_db_cleanup();
}

/* ---------- main --------------------------------------------------------- */

int main(void) {
    rsvp_log_init("tests/test_state_machine.log");
    rsvp_set_log_level(LOG_LEVEL_WARN); /* suppress noise during tests */
    printf("=== test_state_machine ===\n");

    test_path_at_egress_creates_psb_and_sends_resv();
    test_path_at_transit_creates_psb_and_forwards();
    test_path_refresh_does_not_duplicate_psb();
    test_resv_at_ingress_installs_mpls();
    test_resv_at_transit_allocates_label_and_propagates();
    test_pathtear_removes_psb();
    test_resvtear_removes_rsb();
    test_initiate_path_creates_psb();
    test_teardown_path_sends_pathtear();

    TEST_SUMMARY();
}
