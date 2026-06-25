/**
 * @file test_builder.c
 * @brief Unit tests for rsvp_builder — RSVP message construction.
 *
 * Verifies that every builder function encodes values correctly in network
 * byte order, that finalize sets length and checksum, and that buffer
 * overflow is reported rather than silently corrupting memory.
 */

#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "test_framework.h"
#include "common/rsvp_protocol.h"
#include "common/rsvp_error.h"
#include "pi/rsvp_builder.h"

/* ---------- helpers ------------------------------------------------------ */

static void build_minimal_path(uint8_t* buf, size_t bufsz,
                                struct rsvp_builder* b) {
    struct in_addr dest, dummy;
    inet_aton("192.168.1.1", &dest);
    inet_aton("10.0.0.1",   &dummy);

    rsvp_builder_init(b, buf, bufsz, RSVP_MSG_PATH);
    rsvp_builder_add_session_ipv4(b, &dest, 42, &dest);
    rsvp_builder_add_hop_ipv4(b, &dummy, 1);
    rsvp_builder_add_label_request(b, 0x0800);
}

/* ---------- tests -------------------------------------------------------- */

static void test_init_msg_type(void) {
    TEST_BEGIN("init_msg_type");
    uint8_t buf[256];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
    size_t len = rsvp_builder_finalize(&b);
    ASSERT_GT(len, 0u, "finalize returns non-zero length");

    struct rsvp_common_hdr* hdr = (struct rsvp_common_hdr*)buf;
    ASSERT_EQ(hdr->msg_type, RSVP_MSG_PATH, "msg_type = PATH after init");
}

static void test_finalize_sets_length(void) {
    TEST_BEGIN("finalize_sets_length");
    uint8_t buf[256];
    struct rsvp_builder b;
    build_minimal_path(buf, sizeof(buf), &b);
    size_t len = rsvp_builder_finalize(&b);

    struct rsvp_common_hdr* hdr = (struct rsvp_common_hdr*)buf;
    ASSERT_EQ((size_t)ntohs(hdr->msg_length), len, "msg_length field matches returned length");
}

static void test_checksum_nonzero(void) {
    TEST_BEGIN("checksum_nonzero");
    uint8_t buf[256];
    struct rsvp_builder b;
    build_minimal_path(buf, sizeof(buf), &b);
    rsvp_builder_finalize(&b);

    struct rsvp_common_hdr* hdr = (struct rsvp_common_hdr*)buf;
    ASSERT_NE(hdr->cksum, 0u, "checksum is non-zero for non-trivial payload");
}

static void test_version_is_one(void) {
    TEST_BEGIN("version_is_one");
    uint8_t buf[128];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESV);
    rsvp_builder_finalize(&b);

    struct rsvp_common_hdr* hdr = (struct rsvp_common_hdr*)buf;
    ASSERT_EQ((hdr->ver_flags >> 4) & 0xF, 1, "RSVP version field = 1");
}

static void test_add_session_encodes_tunnel_id(void) {
    TEST_BEGIN("add_session_encodes_tunnel_id");
    uint8_t buf[256];
    struct rsvp_builder b;
    struct in_addr dest;
    inet_aton("10.1.2.3", &dest);

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
    rsvp_builder_add_session_ipv4(&b, &dest, 77, &dest);
    rsvp_builder_finalize(&b);

    /* Session object is right after the common header */
    uint8_t* p = buf + sizeof(struct rsvp_common_hdr);
    /* Skip 4-byte object header: length(2) + class(1) + ctype(1) */
    struct rsvp_session_ipv4* sess =
        (struct rsvp_session_ipv4*)(p + 4);
    ASSERT_EQ(ntohs(sess->tunnel_id), 77u, "tunnel_id encoded correctly");
    ASSERT_EQ(sess->dest_addr.s_addr, dest.s_addr, "dest_addr encoded correctly");
}

static void test_add_hop_encodes_address(void) {
    TEST_BEGIN("add_hop_encodes_address");
    uint8_t buf[256];
    struct rsvp_builder b;
    struct in_addr dest, hop;
    inet_aton("10.0.0.2", &dest);
    inet_aton("172.16.0.1", &hop);

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
    rsvp_builder_add_session_ipv4(&b, &dest, 1, &dest);
    rsvp_builder_add_hop_ipv4(&b, &hop, 3);
    rsvp_builder_finalize(&b);

    /* Find PHOP object by scanning for class = RSVP_CLASS_HOP */
    uint8_t* end = buf + ntohs(((struct rsvp_common_hdr*)buf)->msg_length);
    uint8_t* p   = buf + sizeof(struct rsvp_common_hdr);
    bool found = false;
    while (p + 4 < end) {
        uint16_t obj_len   = ntohs(*(uint16_t*)p);
        uint8_t  obj_class = p[2];
        if (obj_class == RSVP_CLASS_HOP) {
            struct rsvp_hop_ipv4* h = (struct rsvp_hop_ipv4*)(p + 4);
            ASSERT_EQ(h->neighbor_addr.s_addr, hop.s_addr, "hop address encoded correctly");
            found = true;
            break;
        }
        if (obj_len < 4) break;
        p += obj_len;
    }
    ASSERT(found, "HOP object present in buffer");
}

static void test_add_label_encodes_value(void) {
    TEST_BEGIN("add_label_encodes_value");
    uint8_t buf[256];
    struct rsvp_builder b;
    struct in_addr dest;
    inet_aton("10.0.0.2", &dest);

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESV);
    rsvp_builder_add_session_ipv4(&b, &dest, 5, &dest);
    rsvp_builder_add_label_ipv4(&b, 12345);
    rsvp_builder_finalize(&b);

    uint8_t* end = buf + ntohs(((struct rsvp_common_hdr*)buf)->msg_length);
    uint8_t* p   = buf + sizeof(struct rsvp_common_hdr);
    bool found = false;
    while (p + 4 < end) {
        uint16_t obj_len   = ntohs(*(uint16_t*)p);
        uint8_t  obj_class = p[2];
        if (obj_class == RSVP_CLASS_LABEL) {
            uint32_t label = ntohl(*(uint32_t*)(p + 4));
            ASSERT_EQ(label, 12345u, "label value encoded in network byte order");
            found = true;
            break;
        }
        if (obj_len < 4) break;
        p += obj_len;
    }
    ASSERT(found, "LABEL object present in buffer");
}

static void test_add_hello_encodes_instances(void) {
    TEST_BEGIN("add_hello_encodes_instances");
    uint8_t buf[128];
    struct rsvp_builder b;

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_HELLO);
    rsvp_builder_add_hello(&b, 0xAABBCCDD, 0x11223344, RSVP_HELLO_CTYPE_REQUEST);
    rsvp_builder_finalize(&b);

    uint8_t* p = buf + sizeof(struct rsvp_common_hdr) + 4; /* skip obj header */
    struct rsvp_hello_obj* ho = (struct rsvp_hello_obj*)p;
    ASSERT_EQ(ntohl(ho->src_instance), 0xAABBCCDDu, "src_instance encoded correctly");
    ASSERT_EQ(ntohl(ho->dst_instance), 0x11223344u, "dst_instance encoded correctly");
}

static void test_hello_ctype_set_correctly(void) {
    TEST_BEGIN("hello_ctype_set_correctly");
    uint8_t buf[128];
    struct rsvp_builder b;

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_HELLO);
    rsvp_builder_add_hello(&b, 1, 2, RSVP_HELLO_CTYPE_ACK);
    rsvp_builder_finalize(&b);

    uint8_t* p = buf + sizeof(struct rsvp_common_hdr);
    ASSERT_EQ(p[2], RSVP_CLASS_HELLO, "object class = RSVP_CLASS_HELLO");
    ASSERT_EQ(p[3], RSVP_HELLO_CTYPE_ACK, "c_type = ACK (2)");
}

static void test_buffer_overflow_returns_error(void) {
    TEST_BEGIN("buffer_overflow_returns_error");
    uint8_t buf[8]; /* far too small for any real message */
    struct rsvp_builder b;
    struct in_addr addr;
    inet_aton("1.2.3.4", &addr);

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
    int rc = rsvp_builder_add_session_ipv4(&b, &addr, 1, &addr);
    ASSERT_NE(rc, RSVP_SUCCESS, "builder returns error on overflow");
}

static void test_resv_msg_type(void) {
    TEST_BEGIN("resv_msg_type");
    uint8_t buf[64];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESV);
    rsvp_builder_finalize(&b);

    struct rsvp_common_hdr* hdr = (struct rsvp_common_hdr*)buf;
    ASSERT_EQ(hdr->msg_type, RSVP_MSG_RESV, "RESV msg_type correct");
}

static void test_pathtear_msg_type(void) {
    TEST_BEGIN("pathtear_msg_type");
    uint8_t buf[64];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATHTEAR);
    rsvp_builder_finalize(&b);

    struct rsvp_common_hdr* hdr = (struct rsvp_common_hdr*)buf;
    ASSERT_EQ(hdr->msg_type, RSVP_MSG_PATHTEAR, "PATHTEAR msg_type correct");
}

/* ---------- main --------------------------------------------------------- */

int main(void) {
    printf("=== test_builder ===\n");

    test_init_msg_type();
    test_finalize_sets_length();
    test_checksum_nonzero();
    test_version_is_one();
    test_add_session_encodes_tunnel_id();
    test_add_hop_encodes_address();
    test_add_label_encodes_value();
    test_add_hello_encodes_instances();
    test_hello_ctype_set_correctly();
    test_buffer_overflow_returns_error();
    test_resv_msg_type();
    test_pathtear_msg_type();

    TEST_SUMMARY();
}
