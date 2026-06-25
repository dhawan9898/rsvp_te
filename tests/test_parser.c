/**
 * @file test_parser.c
 * @brief Unit tests for rsvp_parser — RSVP message decoding.
 *
 * Each test builds a well-formed RSVP message with rsvp_builder, wraps it
 * in a fake IP header (as rsvp_parse_packet() expects), and verifies that
 * the parser extracts every field correctly.
 */

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdbool.h>

#include "test_framework.h"
#include "common/rsvp_protocol.h"
#include "common/rsvp_error.h"
#include "pi/rsvp_builder.h"
#include "pi/rsvp_parser.h"

/* ---------- helpers ------------------------------------------------------ */

static void wrap_in_ip(const uint8_t* rsvp, size_t rsvp_len,
                        uint8_t* out, struct in_addr src, struct in_addr dst) {
    struct iphdr* ip = (struct iphdr*)out;
    memset(ip, 0, sizeof(*ip));
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tot_len  = htons((uint16_t)(sizeof(*ip) + rsvp_len));
    ip->protocol = 46;
    ip->saddr    = src.s_addr;
    ip->daddr    = dst.s_addr;
    memcpy(out + sizeof(*ip), rsvp, rsvp_len);
}

/* ---------- tests -------------------------------------------------------- */

static void test_parse_valid_path(void) {
    TEST_BEGIN("parse_valid_path");

    struct in_addr src, dst;
    inet_aton("10.0.0.1", &src);
    inet_aton("10.0.0.2", &dst);

    uint8_t rsvp[256];
    struct rsvp_builder b;
    rsvp_builder_init(&b, rsvp, sizeof(rsvp), RSVP_MSG_PATH);
    rsvp_builder_add_session_ipv4(&b, &dst, 99, &dst);
    struct rsvp_sender_ipv4 snd;
    memset(&snd, 0, sizeof(snd));
    snd.source_addr = src;
    snd.lsp_id      = htons(1);
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &snd, sizeof(snd));
    rsvp_builder_add_hop_ipv4(&b, &src, 1);
    rsvp_builder_add_label_request(&b, 0x0800);
    size_t rsvp_len = rsvp_builder_finalize(&b);

    uint8_t pkt[512];
    wrap_in_ip(rsvp, rsvp_len, pkt, src, dst);

    struct rsvp_message_info info;
    memset(&info, 0, sizeof(info));
    int rc = rsvp_parse_packet(pkt, sizeof(struct iphdr) + rsvp_len, &info);

    ASSERT_EQ(rc, RSVP_SUCCESS, "parse returns SUCCESS");
    ASSERT_NOTNULL(info.common_hdr, "common_hdr pointer set");
    ASSERT_EQ(info.common_hdr->msg_type, RSVP_MSG_PATH, "msg_type = PATH");
    ASSERT_EQ(ntohs(info.key.session.tunnel_id), 99u, "tunnel_id = 99");
    ASSERT_EQ(info.key.sender.source_addr.s_addr, src.s_addr, "sender source_addr");
    ASSERT_EQ(ntohs(info.key.sender.lsp_id), 1u, "lsp_id = 1");
    ASSERT_NOTNULL(info.hop_obj, "hop object parsed");
    ASSERT_NOTNULL(info.label_req, "label_request object parsed");
}

static void test_parse_hello_request(void) {
    TEST_BEGIN("parse_hello_request");

    struct in_addr src, dst;
    inet_aton("10.0.0.1", &src);
    inet_aton("10.0.0.2", &dst);

    uint8_t rsvp[64];
    struct rsvp_builder b;
    rsvp_builder_init(&b, rsvp, sizeof(rsvp), RSVP_MSG_HELLO);
    rsvp_builder_add_hello(&b, 0xDEADBEEF, 0, RSVP_HELLO_CTYPE_REQUEST);
    size_t rsvp_len = rsvp_builder_finalize(&b);

    uint8_t pkt[256];
    wrap_in_ip(rsvp, rsvp_len, pkt, src, dst);

    struct rsvp_message_info info;
    memset(&info, 0, sizeof(info));
    int rc = rsvp_parse_packet(pkt, sizeof(struct iphdr) + rsvp_len, &info);

    ASSERT_EQ(rc, RSVP_SUCCESS, "parse returns SUCCESS");
    ASSERT_EQ(info.common_hdr->msg_type, RSVP_MSG_HELLO, "msg_type = HELLO");
    ASSERT_NOTNULL(info.hello_obj, "hello_obj pointer set");
    ASSERT_EQ(info.hello_ctype, (uint8_t)RSVP_HELLO_CTYPE_REQUEST, "c_type = REQUEST (1)");
    ASSERT_EQ(ntohl(info.hello_obj->src_instance), 0xDEADBEEFu, "src_instance decoded");
}

static void test_parse_hello_ack(void) {
    TEST_BEGIN("parse_hello_ack");

    struct in_addr src, dst;
    inet_aton("10.0.0.1", &src);
    inet_aton("10.0.0.2", &dst);

    uint8_t rsvp[64];
    struct rsvp_builder b;
    rsvp_builder_init(&b, rsvp, sizeof(rsvp), RSVP_MSG_HELLO);
    rsvp_builder_add_hello(&b, 0x12345678, 0xABCDEF01, RSVP_HELLO_CTYPE_ACK);
    size_t rsvp_len = rsvp_builder_finalize(&b);

    uint8_t pkt[256];
    wrap_in_ip(rsvp, rsvp_len, pkt, src, dst);

    struct rsvp_message_info info;
    memset(&info, 0, sizeof(info));
    rsvp_parse_packet(pkt, sizeof(struct iphdr) + rsvp_len, &info);

    ASSERT_EQ(info.hello_ctype, (uint8_t)RSVP_HELLO_CTYPE_ACK, "c_type = ACK (2)");
    ASSERT_EQ(ntohl(info.hello_obj->dst_instance), 0xABCDEF01u, "dst_instance decoded");
}

static void test_parse_resv(void) {
    TEST_BEGIN("parse_resv");

    struct in_addr src, dst;
    inet_aton("10.0.0.2", &src);
    inet_aton("10.0.0.1", &dst);

    uint8_t rsvp[256];
    struct rsvp_builder b;
    rsvp_builder_init(&b, rsvp, sizeof(rsvp), RSVP_MSG_RESV);
    rsvp_builder_add_session_ipv4(&b, &dst, 7, &dst);
    rsvp_builder_add_hop_ipv4(&b, &src, 2);
    rsvp_builder_add_style(&b, RSVP_STYLE_FF);
    struct rsvp_sender_ipv4 snd;
    memset(&snd, 0, sizeof(snd));
    snd.source_addr = dst;
    snd.lsp_id      = htons(1);
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7, &snd, sizeof(snd));
    rsvp_builder_add_label_ipv4(&b, 5000);
    size_t rsvp_len = rsvp_builder_finalize(&b);

    uint8_t pkt[512];
    wrap_in_ip(rsvp, rsvp_len, pkt, src, dst);

    struct rsvp_message_info info;
    memset(&info, 0, sizeof(info));
    int rc = rsvp_parse_packet(pkt, sizeof(struct iphdr) + rsvp_len, &info);

    ASSERT_EQ(rc, RSVP_SUCCESS, "parse returns SUCCESS");
    ASSERT_EQ(info.common_hdr->msg_type, RSVP_MSG_RESV, "msg_type = RESV");
    ASSERT_NOTNULL(info.label_obj, "label object parsed");
}

static void test_parse_pathtear(void) {
    TEST_BEGIN("parse_pathtear");

    struct in_addr src, dst;
    inet_aton("10.0.0.1", &src);
    inet_aton("10.0.0.2", &dst);

    uint8_t rsvp[256];
    struct rsvp_builder b;
    rsvp_builder_init(&b, rsvp, sizeof(rsvp), RSVP_MSG_PATHTEAR);
    rsvp_builder_add_session_ipv4(&b, &dst, 3, &dst);
    rsvp_builder_add_hop_ipv4(&b, &src, 1);
    struct rsvp_sender_ipv4 snd;
    memset(&snd, 0, sizeof(snd));
    snd.source_addr = src;
    snd.lsp_id      = htons(1);
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &snd, sizeof(snd));
    size_t rsvp_len = rsvp_builder_finalize(&b);

    uint8_t pkt[512];
    wrap_in_ip(rsvp, rsvp_len, pkt, src, dst);

    struct rsvp_message_info info;
    memset(&info, 0, sizeof(info));
    int rc = rsvp_parse_packet(pkt, sizeof(struct iphdr) + rsvp_len, &info);

    ASSERT_EQ(rc, RSVP_SUCCESS, "parse returns SUCCESS");
    ASSERT_EQ(info.common_hdr->msg_type, RSVP_MSG_PATHTEAR, "msg_type = PATHTEAR");
}

static void test_parse_ero_single_hop(void) {
    TEST_BEGIN("parse_ero_single_hop");

    struct in_addr src, dst, hop;
    inet_aton("10.0.0.1", &src);
    inet_aton("10.0.0.5", &dst);
    inet_aton("10.0.0.2", &hop);

    struct rsvp_ero_ipv4_subobj ero[1];
    memset(ero, 0, sizeof(ero));
    ero[0].l_type  = 0x01; /* strict, IPv4 */
    ero[0].length  = 8;
    ero[0].address = hop;
    ero[0].prefix  = 32;

    uint8_t rsvp[256];
    struct rsvp_builder b;
    rsvp_builder_init(&b, rsvp, sizeof(rsvp), RSVP_MSG_PATH);
    rsvp_builder_add_session_ipv4(&b, &dst, 10, &dst);
    struct rsvp_sender_ipv4 snd;
    memset(&snd, 0, sizeof(snd));
    snd.source_addr = src;
    snd.lsp_id      = htons(1);
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &snd, sizeof(snd));
    rsvp_builder_add_hop_ipv4(&b, &src, 1);
    rsvp_builder_add_label_request(&b, 0x0800);
    rsvp_builder_add_ero(&b, ero, 1);
    size_t rsvp_len = rsvp_builder_finalize(&b);

    uint8_t pkt[512];
    wrap_in_ip(rsvp, rsvp_len, pkt, src, dst);

    struct rsvp_message_info info;
    memset(&info, 0, sizeof(info));
    rsvp_parse_packet(pkt, sizeof(struct iphdr) + rsvp_len, &info);

    ASSERT_GT(info.ero_count, 0u, "ERO hop count > 0");
    ASSERT_EQ(info.ero[0].address.s_addr, hop.s_addr, "ERO first hop address correct");
}

static void test_parse_truncated_rejected(void) {
    TEST_BEGIN("parse_truncated_rejected");

    struct in_addr src, dst;
    inet_aton("10.0.0.1", &src);
    inet_aton("10.0.0.2", &dst);

    uint8_t buf[256];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
    rsvp_builder_add_session_ipv4(&b, &dst, 1, &dst);
    size_t rsvp_len = rsvp_builder_finalize(&b);

    uint8_t pkt[512];
    wrap_in_ip(buf, rsvp_len, pkt, src, dst);

    /* Pass only half the bytes to simulate truncation */
    struct rsvp_message_info info;
    memset(&info, 0, sizeof(info));
    int rc = rsvp_parse_packet(pkt, 4, &info); /* just 4 bytes — too short */
    ASSERT_NE(rc, RSVP_SUCCESS, "truncated packet rejected");
}

static void test_parse_src_ip_captured(void) {
    TEST_BEGIN("parse_src_ip_captured");

    struct in_addr src, dst;
    inet_aton("172.16.0.10", &src);
    inet_aton("172.16.0.20", &dst);

    uint8_t rsvp[128];
    struct rsvp_builder b;
    rsvp_builder_init(&b, rsvp, sizeof(rsvp), RSVP_MSG_HELLO);
    rsvp_builder_add_hello(&b, 1, 0, RSVP_HELLO_CTYPE_REQUEST);
    size_t rsvp_len = rsvp_builder_finalize(&b);

    uint8_t pkt[256];
    wrap_in_ip(rsvp, rsvp_len, pkt, src, dst);

    struct rsvp_message_info info;
    memset(&info, 0, sizeof(info));
    rsvp_parse_packet(pkt, sizeof(struct iphdr) + rsvp_len, &info);

    ASSERT_EQ(info.src_ip.s_addr, src.s_addr, "src IP extracted from IP header");
}

/* ---------- main --------------------------------------------------------- */

int main(void) {
    printf("=== test_parser ===\n");

    test_parse_valid_path();
    test_parse_hello_request();
    test_parse_hello_ack();
    test_parse_resv();
    test_parse_pathtear();
    test_parse_ero_single_hop();
    test_parse_truncated_rejected();
    test_parse_src_ip_captured();

    TEST_SUMMARY();
}
