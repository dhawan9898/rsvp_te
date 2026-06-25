/**
 * @file rsvp_protocol.h
 * @brief RSVP-TE protocol definitions and structures.
 * @details Contains message types, object classes, and structure definitions conforming to RFC 2205, RFC 3209, etc.
 */

#ifndef RSVP_PROTOCOL_H
#define RSVP_PROTOCOL_H

#include <netinet/in.h>
#include <stdint.h>

/** @name RSVP Message Types (RFC 2205)
 *  @{
 */
#define RSVP_MSG_PATH 1
#define RSVP_MSG_RESV 2
#define RSVP_MSG_PATHERR 3
#define RSVP_MSG_RESVERR 4
#define RSVP_MSG_PATHTEAR 5
#define RSVP_MSG_RESVTEAR 6
#define RSVP_MSG_RESVCONF 7
#define RSVP_MSG_SREFRESH 15 /**< RFC 2961 */
/** @} */

/** @name RSVP Object Classes (RFC 2205 / 3209)
 *  @{
 */
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
/** @} */

/** @name RSVP Object Classes — FRR extensions (RFC 4090)
 *  @{
 */
#define RSVP_CLASS_FAST_REROUTE 205 /**< FAST_REROUTE object — requests FRR protection */
#define RSVP_CLASS_DETOUR       63  /**< DETOUR object — identifies PLR and avoided node */
/** @} */

/** @name ERO / RRO Subobject Types (RFC 3209)
 *  @{
 */
#define RSVP_ERO_IPV4 1 /**< IPv4 prefix subobject */
/** @} */

/** @name ERO Subobject flags
 *  @{
 */
#define RSVP_ERO_LOOSE  0x80 /**< Bit 7 set → loose hop; clear → strict hop */
/** @} */

/** @name SESSION_ATTRIBUTE flags (RFC 3209 §4.7.2 + RFC 4090 §4.2)
 *  @{
 */
#define RSVP_SESSATTR_LOCAL_PROT_DESIRED  0x01 /**< Request local protection at each hop */
#define RSVP_SESSATTR_LABEL_RECORDING     0x02 /**< Request label recording in RRO */
#define RSVP_SESSATTR_SE_STYLE            0x04 /**< Shared-Explicit merge style desired */
#define RSVP_SESSATTR_LOCAL_PROT_IN_USE   0x08 /**< FRR: local protection is currently active */
#define RSVP_SESSATTR_NODE_PROTECTION     0x10 /**< FRR: node protection is in use */
#define RSVP_SESSATTR_BW_PROTECTION       0x20 /**< FRR: bandwidth protection is in use */
/** @} */

/** @name FAST_REROUTE object flags (RFC 4090 §4.1)
 *  @{
 */
#define RSVP_FRR_FLAG_ONE_TO_ONE 0x01 /**< One-to-one backup (detour LSP per protected LSP) */
#define RSVP_FRR_FLAG_FACILITY   0x02 /**< Facility backup (shared bypass tunnel) */
/** @} */

/**
 * @brief ERO IPv4 Subobject.
 * @details Represents an explicit route IPv4 subobject.
 */
struct rsvp_ero_ipv4_subobj {
    uint8_t type;       /**< Bit 7: Loose/Strict, Bits 0-6: Type */
    uint8_t length;     /**< Length of subobject */
    struct in_addr addr;/**< IPv4 address */
    uint8_t prefix_len; /**< Prefix length */
    uint8_t res;        /**< Reserved */
} __attribute__((packed));

/**
 * @brief RSVP Common Header.
 * @details Common header for all RSVP messages as per RFC 2205.
 */
struct rsvp_common_hdr {
    uint8_t ver_flags;  /**< Version (4 bits) | Flags (4 bits) */
    uint8_t msg_type;   /**< Message type */
    uint16_t checksum;  /**< Message checksum */
    uint8_t ttl;        /**< Time to Live */
    uint8_t reserved;   /**< Reserved */
    uint16_t length;    /**< Total message length */
} __attribute__((packed));

/**
 * @brief RSVP Object Header.
 * @details Header for each RSVP object as per RFC 2205.
 */
struct rsvp_obj_hdr {
    uint16_t length;    /**< Object length */
    uint8_t class_num;  /**< Object class number */
    uint8_t c_type;     /**< Object C-Type */
} __attribute__((packed));

/**
 * @brief TIME_VALUES Object.
 * @details Defines the refresh period for RSVP states (RFC 2205).
 */
struct rsvp_time_values {
    uint32_t refresh_ms; /**< Refresh period in milliseconds */
} __attribute__((packed));

/**
 * @brief ERROR_SPEC Object - IPv4.
 * @details Defines the error specification for IPv4 nodes (RFC 2205).
 */
struct rsvp_error_spec_ipv4 {
    struct in_addr error_node; /**< IP address of the node that detected the error */
    uint8_t flags;             /**< Error flags */
    uint8_t error_code;        /**< Error code */
    uint16_t error_value;      /**< Error value */
} __attribute__((packed));

/**
 * @brief LABEL_REQUEST Object.
 * @details Requests a label binding for a particular LSP (RFC 3209).
 */
struct rsvp_label_request {
    uint16_t reserved; /**< Reserved */
    uint16_t l3pid;    /**< Layer 3 Protocol ID */
} __attribute__((packed));

/** @name RSVP Message lengths and constants
 *  @{
 */
#define RSVP_VERSION 1
#define RSVP_HER_LEN sizeof(struct rsvp_common_hdr)
#define RSVP_OBJ_HDR_LEN sizeof(struct rsvp_obj_hdr)
/** @} */

/**
 * @brief Helper macros for buffer manipulation.
 * @param len The length to be aligned.
 */
#define RSVP_ALIGN(len) (((len) + 3) & ~3)

/**
 * @brief Session Object - LSP_TUNNEL_IPv4.
 * @details Identifies a specific IPv4 LSP Tunnel (RFC 3209).
 */
struct rsvp_session_ipv4 {
    struct in_addr dest_addr;          /**< IPv4 tunnel destination address */
    uint16_t reserved;                 /**< Reserved */
    uint16_t tunnel_id;                /**< Tunnel ID */
    struct in_addr extended_tunnel_id; /**< Extended Tunnel ID */
} __attribute__((packed));

/**
 * @brief Session Object - LSP_TUNNEL_IPv6.
 * @details Identifies a specific IPv6 LSP Tunnel (RFC 3209).
 */
struct rsvp_session_ipv6 {
    struct in6_addr dest_addr;          /**< IPv6 tunnel destination address */
    uint16_t reserved;                  /**< Reserved */
    uint16_t tunnel_id;                 /**< Tunnel ID */
    struct in6_addr extended_tunnel_id; /**< Extended Tunnel ID */
} __attribute__((packed));

/**
 * @brief RSVP HOP Object - IPv4.
 * @details Carries the IPv4 address of the RSVP-capable node that sent this message (RFC 2205).
 */
struct rsvp_hop_ipv4 {
    struct in_addr neighbor_addr;  /**< Neighbor's IPv4 address */
    uint32_t logical_interface;    /**< Logical interface handle */
} __attribute__((packed));

/**
 * @brief RSVP HOP Object - IPv6.
 * @details Carries the IPv6 address of the RSVP-capable node that sent this message (RFC 2205).
 */
struct rsvp_hop_ipv6 {
    struct in6_addr neighbor_addr; /**< Neighbor's IPv6 address */
    uint32_t logical_interface;    /**< Logical interface handle */
} __attribute__((packed));

/**
 * @brief INTEGRITY Object.
 * @details Provides cryptographic authentication for RSVP messages (RFC 2747).
 */
struct rsvp_integrity {
    uint8_t flags;           /**< Flags */
    uint8_t reserved;        /**< Reserved */
    uint8_t key_id[6];       /**< Key Identifier */
    uint64_t sequence_number;/**< Sequence number to prevent replay attacks */
    uint8_t digest[];        /**< Variable length digest */
} __attribute__((packed));

/**
 * @brief Sender Template / Filter Spec - LSP_TUNNEL_IPv4.
 * @details Identifies the sender of the LSP Tunnel for IPv4 (RFC 3209).
 */
struct rsvp_sender_ipv4 {
    struct in_addr source_addr; /**< Sender's IPv4 address */
    uint16_t reserved;          /**< Reserved */
    uint16_t lsp_id;            /**< LSP ID */
} __attribute__((packed));

/**
 * @brief Sender Template / Filter Spec - LSP_TUNNEL_IPv6.
 * @details Identifies the sender of the LSP Tunnel for IPv6 (RFC 3209).
 */
struct rsvp_sender_ipv6 {
    struct in6_addr source_addr; /**< Sender's IPv6 address */
    uint16_t reserved;           /**< Reserved */
    uint16_t lsp_id;             /**< LSP ID */
} __attribute__((packed));

/**
 * @brief Sender TSpec Object.
 * @details Full IntServ Token Bucket describing traffic characteristics (RFC 2210).
 */
struct rsvp_sender_tspec {
    uint8_t version;           /**< IntServ version (usually 0) */
    uint8_t reserved;          /**< Reserved */
    uint16_t length;           /**< Overall length in words minus 1 */
    uint8_t service_hdr;       /**< Service number (e.g. 5 for Controlled-Load) */
    uint8_t reserved2;         /**< Reserved */
    uint16_t svc_length;       /**< Length of service data */
    uint8_t param_id;          /**< Parameter ID (127 for Token Bucket TSpec) */
    uint8_t flags;             /**< Flags */
    uint16_t param_length;     /**< Length of parameter data */
    float token_bucket_rate;   /**< Bytes/sec (IEEE floating point) */
    float token_bucket_size;   /**< Bytes */
    float peak_data_rate;      /**< Bytes/sec */
    uint32_t min_policed_unit; /**< Bytes */
    uint32_t max_packet_size;  /**< Bytes */
} __attribute__((packed));

/**
 * @brief Style Object.
 * @details Describes the reservation style (RFC 2205).
 */
struct rsvp_style {
    uint32_t style; /**< Option Vector (24 bits) + Style ID (8 bits) */
} __attribute__((packed));

/** @name Reservation Styles
 *  @{
 */
#define RSVP_STYLE_FF 10 /**< Fixed Filter */
#define RSVP_STYLE_SE 18 /**< Shared Explicit */
/** @} */

/**
 * @brief AdSpec Object.
 * @details Carries advertisement data for IntServ (RFC 2205).
 */
struct rsvp_adspec {
    uint8_t version; /**< AdSpec version */
    uint8_t reserved;/**< Reserved */
    uint16_t length; /**< AdSpec length */
    /* Parameter list follows... */
} __attribute__((packed));

/**
 * @brief Label Object - IPv4.
 * @details Specifies the allocated label (RFC 3209).
 */
struct rsvp_label_ipv4 {
    uint32_t label; /**< 20-bit MPLS label value, right-aligned (RFC 3209) */
} __attribute__((packed));

/** @name RSVP Protocol Error Codes (RFC 2205)
 *  @{
 */
#define RSVP_PROTO_ERR_NONE 0
#define RSVP_PROTO_ERR_ADMISSION_CONTROL 1
#define RSVP_PROTO_ERR_POLICY_CONTROL 2
#define RSVP_PROTO_ERR_NO_PATH_STATE 3
#define RSVP_PROTO_ERR_NO_RESV_STATE 4
#define RSVP_PROTO_ERR_CONF_PREEMPT 5
#define RSVP_PROTO_ERR_UNKNOWN_CLASS 6
#define RSVP_PROTO_ERR_UNKNOWN_C_TYPE 7
#define RSVP_PROTO_ERR_ADMISSION_CONTROL_FAILURE 11
#define RSVP_PROTO_ERR_TRAFFIC_CONTROL_ERROR 12
#define RSVP_PROTO_ERR_UNKNOWN_OBJECT_CLASS 13
#define RSVP_PROTO_ERR_UNKNOWN_OBJECT_C_TYPE 14
#define RSVP_PROTO_ERR_API_ERROR 20
#define RSVP_PROTO_ERR_TRAFFIC_CONTROL_SYSTEM_ERROR 21
#define RSVP_PROTO_ERR_RSVP_SYSTEM_ERROR 22
#define RSVP_PROTO_ERR_ROUTING_PROBLEM 24
/** @} */

/**
 * @brief FAST_REROUTE Object payload (RFC 4090 §4.1, Class 205, C-Type 1).
 * @details Carried in PATH messages to request FRR protection at transit LSRs.
 *          The bandwidth field uses the same IEEE 754 encoding as SENDER_TSPEC.
 */
struct rsvp_fast_reroute {
    uint8_t  setup_prio;   /**< Setup priority for bypass/detour LSP */
    uint8_t  holding_prio; /**< Holding priority for bypass/detour LSP */
    uint8_t  hop_limit;    /**< Maximum number of hops for backup path */
    uint8_t  flags;        /**< RSVP_FRR_FLAG_ONE_TO_ONE or RSVP_FRR_FLAG_FACILITY */
    uint32_t bandwidth;    /**< Bandwidth to protect (IEEE float, network byte order) */
    uint32_t include_any;  /**< Include-any affinity constraint */
    uint32_t exclude_any;  /**< Exclude-any affinity constraint */
    uint32_t include_all;  /**< Include-all affinity constraint */
} __attribute__((packed));

/**
 * @brief DETOUR Object payload — IPv4 (RFC 4090 §4.2, Class 63, C-Type 7).
 * @details Identifies the Point of Local Repair and the avoided node/link.
 */
struct rsvp_detour_ipv4 {
    struct in_addr plr_id;        /**< IPv4 address of the Point of Local Repair */
    struct in_addr avoid_node_id; /**< IPv4 address of the avoided node */
} __attribute__((packed));

/**
 * @brief SESSION_ATTRIBUTE Object (C-Type 7).
 * @details Session attribute without resource affinities for LSP_TUNNEL_IPv4 (RFC 3209).
 */
struct rsvp_session_attribute {
    uint8_t setup_prio;   /**< Setup priority */
    uint8_t holding_prio; /**< Holding priority */
    uint8_t flags;        /**< Flags */
    uint8_t name_length;  /**< Length of session name */
    char name[];          /**< Variable length name, padded to 4 bytes */
} __attribute__((packed));

/**
 * @brief SESSION_ATTRIBUTE Object (C-Type 1).
 * @details Session attribute with resource affinities for LSP_TUNNEL_IPv4 (RFC 3209).
 */
struct rsvp_session_attribute_ra {
    uint32_t exclude_any; /**< Exclude any affinity */
    uint32_t include_any; /**< Include any affinity */
    uint32_t include_all; /**< Include all affinity */
    uint8_t setup_prio;   /**< Setup priority */
    uint8_t holding_prio; /**< Holding priority */
    uint8_t flags;        /**< Flags */
    uint8_t name_length;  /**< Length of session name */
    char name[];          /**< Variable length name, padded to 4 bytes */
} __attribute__((packed));

#endif /* RSVP_PROTOCOL_H */
