#ifndef RSVP_PROTOCOL_H
#define RSVP_PROTOCOL_H

#include <netinet/in.h>
#include <stdint.h>

/* RSVP Message Types (RFC 2205) */
#define RSVP_MSG_PATH 1
#define RSVP_MSG_RESV 2
#define RSVP_MSG_PATHERR 3
#define RSVP_MSG_RESVERR 4
#define RSVP_MSG_PATHTEAR 5
#define RSVP_MSG_RESVTEAR 6
#define RSVP_MSG_RESVCONF 7
#define RSVP_MSG_SREFRESH 15 /* RFC 2961 */

/* RSVP Object Classes (RFC 2205 / 3209) */
#define RSVP_CLASS_SESSION 1
#define RSVP_CLASS_HOP 3
#define RSVP_CLASS_INTEGRITY 4
#define RSVP_CLASS_TIME_VALUES 5
#define RSVP_CLASS_ERROR_SPEC 6
#define RSVP_CLASS_SCOPE 7
#define RSVP_CLASS_STYLE 8
#define RSVP_CLASS_FLOWSPEC 9
#define RSVP_CLASS_FILTER_SPEC 10
#define RSVP_CLASS_SENDER_TEMPLATE 11
#define RSVP_CLASS_SENDER_TSPEC 12
#define RSVP_CLASS_ADSPEC 13
#define RSVP_CLASS_LABEL 16
#define RSVP_CLASS_LABEL_REQUEST 19
#define RSVP_CLASS_EXPLICIT_ROUTE 20
#define RSVP_CLASS_RECORD_ROUTE 21
#define RSVP_CLASS_SESSION_ATTRIB 207

/* ERO Subobjects (RFC 3209) */
#define RSVP_ERO_IPV4 1

struct rsvp_ero_ipv4_subobj {
    uint8_t type; /* Bit 7: Loose/Strict, Bits 0-6: Type */
    uint8_t length;
    struct in_addr addr;
    uint8_t prefix_len;
    uint8_t res;
} __attribute__((packed));

/* Common Header (RFC 2205) */
struct rsvp_common_hdr {
    uint8_t ver_flags; /* Version (4 bits) | Flags (4 bits) */
    uint8_t msg_type;
    uint16_t checksum;
    uint8_t ttl;
    uint8_t reserved;
    uint16_t length;
} __attribute__((packed));

/* Object Header (RFC 2205) */
struct rsvp_obj_hdr {
    uint16_t length;
    uint8_t class_num;
    uint8_t c_type;
} __attribute__((packed));

/* TIME_VALUES Object (RFC 2205) */
struct rsvp_time_values {
    uint32_t refresh_ms;
} __attribute__((packed));

/* ERROR_SPEC Object - IPv4 (RFC 2205) */
struct rsvp_error_spec_ipv4 {
    struct in_addr error_node;
    uint8_t flags;
    uint8_t error_code;
    uint16_t error_value;
} __attribute__((packed));

/* LABEL_REQUEST Object (RFC 3209) */
struct rsvp_label_request {
    uint16_t reserved;
    uint16_t l3pid;
} __attribute__((packed));

/* RSVP Message lengths and constants */
#define RSVP_VERSION 1
#define RSVP_HER_LEN sizeof(struct rsvp_common_hdr)
#define RSVP_OBJ_HDR_LEN sizeof(struct rsvp_obj_hdr)

/* Helper macros for buffer manipulation */
#define RSVP_ALIGN(len) (((len) + 3) & ~3)

/* Session Object - LSP_TUNNEL_IPv4 (RFC 3209) */
struct rsvp_session_ipv4 {
    struct in_addr dest_addr;
    uint16_t reserved;
    uint16_t tunnel_id;
    struct in_addr extended_tunnel_id;
} __attribute__((packed));

/* Session Object - LSP_TUNNEL_IPv6 (RFC 3209) */
struct rsvp_session_ipv6 {
    struct in6_addr dest_addr;
    uint16_t reserved;
    uint16_t tunnel_id;
    struct in6_addr extended_tunnel_id;
} __attribute__((packed));

/* RSVP HOP Object - IPv4 (RFC 2205) */
struct rsvp_hop_ipv4 {
    struct in_addr neighbor_addr;
    uint32_t logical_interface;
} __attribute__((packed));

/* RSVP HOP Object - IPv6 (RFC 2205) */
struct rsvp_hop_ipv6 {
    struct in6_addr neighbor_addr;
    uint32_t logical_interface;
} __attribute__((packed));

/* Sender Template / Filter Spec - LSP_TUNNEL_IPv4 (RFC 3209) */
struct rsvp_sender_ipv4 {
    struct in_addr source_addr;
    uint16_t reserved;
    uint16_t lsp_id;
} __attribute__((packed));

/* Sender Template / Filter Spec - LSP_TUNNEL_IPv6 (RFC 3209) */
struct rsvp_sender_ipv6 {
    struct in6_addr source_addr;
    uint16_t reserved;
    uint16_t lsp_id;
} __attribute__((packed));

/* Sender TSpec Object (RFC 2210) - Full IntServ Token Bucket */
struct rsvp_sender_tspec {
    uint8_t version; /* IntServ version (usually 0) */
    uint8_t reserved;
    uint16_t length;     /* Overall length in words minus 1 */
    uint8_t service_hdr; /* Service number (e.g. 5 for Controlled-Load) */
    uint8_t reserved2;
    uint16_t svc_length; /* Length of service data */
    uint8_t param_id;    /* Parameter ID (127 for Token Bucket TSpec) */
    uint8_t flags;
    uint16_t param_length;     /* Length of parameter data */
    float token_bucket_rate;   /* Bytes/sec (IEEE floating point) */
    float token_bucket_size;   /* Bytes */
    float peak_data_rate;      /* Bytes/sec */
    uint32_t min_policed_unit; /* Bytes */
    uint32_t max_packet_size;  /* Bytes */
} __attribute__((packed));

/* Style Object (RFC 2205) */
struct rsvp_style {
    uint32_t style; /* Option Vector (24 bits) + Style ID (8 bits) */
} __attribute__((packed));

#define RSVP_STYLE_FF 10 /* Fixed Filter */
#define RSVP_STYLE_SE 18 /* Shared Explicit */

/* AdSpec Object (RFC 2205) */
struct rsvp_adspec {
    uint8_t version;
    uint8_t reserved;
    uint16_t length;
    /* Parameter list follows... */
} __attribute__((packed));

/* Label Object - IPv4 (RFC 3209) */
struct rsvp_label_ipv4 {
    uint32_t label; /* 20 bits label, 3 bits EXP, 1 bit S, 8 bits TTL */
} __attribute__((packed));

/* RSVP Error Codes (RFC 2205) */
#define RSVP_ERR_NONE 0
#define RSVP_ERR_ADMISSION_CONTROL 1
#define RSVP_ERR_POLICY_CONTROL 2
#define RSVP_ERR_NO_PATH_STATE 3
#define RSVP_ERR_NO_RESV_STATE 4
#define RSVP_ERR_CONF_PREEMPT 5
#define RSVP_ERR_UNKNOWN_CLASS 6
#define RSVP_ERR_UNKNOWN_C_TYPE 7
#define RSVP_ERR_ADMISSION_CONTROL_FAILURE 11
#define RSVP_ERR_TRAFFIC_CONTROL_ERROR 12
#define RSVP_ERR_UNKNOWN_OBJECT_CLASS 13
#define RSVP_ERR_UNKNOWN_OBJECT_C_TYPE 14
#define RSVP_ERR_API_ERROR 20
#define RSVP_ERR_TRAFFIC_CONTROL_SYSTEM_ERROR 21
#define RSVP_ERR_RSVP_SYSTEM_ERROR 22
#define RSVP_ERR_ROUTING_PROBLEM 24

/* SESSION_ATTRIBUTE Object (RFC 3209) */
/* C-Type 7: LSP_TUNNEL_IPv4 */
struct rsvp_session_attribute {
    uint8_t setup_prio;
    uint8_t holding_prio;
    uint8_t flags;
    uint8_t name_length;
    char name[]; /* Variable length, padded to 4 bytes */
} __attribute__((packed));

/* C-Type 1: LSP_TUNNEL_IPv4 with Resource Affinities */
struct rsvp_session_attribute_ra {
    uint32_t exclude_any;
    uint32_t include_any;
    uint32_t include_all;
    uint8_t setup_prio;
    uint8_t holding_prio;
    uint8_t flags;
    uint8_t name_length;
    char name[]; /* Variable length, padded to 4 bytes */
} __attribute__((packed));

#endif /* RSVP_PROTOCOL_H */
