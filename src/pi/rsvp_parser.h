/**
 * @file rsvp_parser.h
 * @brief RSVP Packet Parser.
 * @details Extracts and validates RSVP objects from raw packets and populates the message info structure.
 */

#ifndef RSVP_PARSER_H
#define RSVP_PARSER_H

#include <stddef.h>

#include "common/rsvp_error.h"
#include "rsvp_protocol.h"
#include "rsvp_state.h"

/**
 * @brief Parsed RSVP Message Info
 * @details Contains pointers to the parsed objects within the received packet buffer.
 */
struct rsvp_message_info {
    struct rsvp_common_hdr* common_hdr; /**< Pointer to the common header */
    struct in_addr src_ip;              /**< Source IP address from the IP header */
    struct in_addr dst_ip;              /**< Destination IP address from the IP header */
    struct rsvp_path_key key;           /**< Parsed path state key */
    uint8_t* payload;                   /**< Pointer to the start of the RSVP object payload */
    size_t payload_len;                 /**< Length of the RSVP payload */

    /* Pointers to objects of interest (NULL if not present) */
    struct rsvp_session_ipv4* sess_v4;
    struct rsvp_session_ipv6* sess_v6;
    struct rsvp_hop_ipv4* hop_v4;
    struct rsvp_hop_ipv6* hop_v6;
    struct rsvp_sender_ipv4* sender_v4;
    struct rsvp_sender_ipv6* sender_v6;
    struct rsvp_time_values* time_values;
    struct rsvp_error_spec_ipv4* error_spec;
    struct rsvp_integrity* integrity;
    struct rsvp_sender_tspec* tspec;
    struct rsvp_sender_tspec* flowspec;
    struct rsvp_adspec* adspec;
    struct rsvp_style* style;
    struct rsvp_ero_ipv4_subobj* ero;
    size_t ero_len;
    struct rsvp_label_ipv4* label;
    struct rsvp_label_request* label_req;
    struct rsvp_session_attribute* sess_attr;
    struct rsvp_session_attribute_ra* sess_attr_ra;
    char lsp_name[256];                 /**< Extracted LSP tunnel name */
};

/**
 * @brief Parse a raw RSVP packet.
 * @details Validates the IP and RSVP headers, verifies the checksum, and extracts known objects into the info structure.
 * @param [in] buffer Pointer to the raw packet buffer (starting with the IP header).
 * @param [in] len Total length of the received packet.
 * @param [out] info Pointer to the structure to populate with parsed object data.
 * @return RSVP_SUCCESS on success, or an rsvp_error_t code on parse error.
 */
rsvp_error_t rsvp_parse_packet(const uint8_t* buffer, size_t len,
                               struct rsvp_message_info* info);

#endif /* RSVP_PARSER_H */
