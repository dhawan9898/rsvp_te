#ifndef RSVP_PARSER_H
#define RSVP_PARSER_H

#include "rsvp_protocol.h"
#include "rsvp_state.h"
#include <stddef.h>

/**
 * Parsed RSVP Message Info
 */
struct rsvp_message_info {
    struct rsvp_common_hdr *common_hdr;
    struct rsvp_path_key    key;
    uint8_t                *payload;
    size_t                  payload_len;
    
    /* Objects of interest */
    struct rsvp_session_ipv4    *sess_v4;
    struct rsvp_session_ipv6    *sess_v6;
    struct rsvp_hop_ipv4        *hop_v4;
    struct rsvp_hop_ipv6        *hop_v6;
    struct rsvp_sender_ipv4     *sender_v4;
    struct rsvp_sender_ipv6     *sender_v6;
    struct rsvp_time_values     *time_values;
    struct rsvp_error_spec_ipv4 *error_spec;
    struct rsvp_sender_tspec    *tspec;
    struct rsvp_adspec          *adspec;
    struct rsvp_ero_ipv4_subobj *ero;
    size_t                       ero_len;
    struct rsvp_label_ipv4      *label;
    struct rsvp_label_request   *label_req;
    struct rsvp_session_attribute *sess_attr;
    char                         lsp_name[256];
};

/**
 * Parse a raw RSVP packet (including IP header if present).
 * Returns 0 on success, -1 on parse error.
 */
int rsvp_parse_packet(uint8_t *buffer, size_t len, struct rsvp_message_info *info);

#endif /* RSVP_PARSER_H */
