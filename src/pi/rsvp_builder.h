#ifndef RSVP_BUILDER_H
#define RSVP_BUILDER_H

#include <stddef.h>

#include "rsvp_protocol.h"

struct rsvp_builder {
    uint8_t* buffer;
    size_t size;
    size_t offset;
    struct rsvp_common_hdr* hdr;
};

/**
 * Initialize a builder with a buffer.
 */
void rsvp_builder_init(struct rsvp_builder* b, uint8_t* buffer, size_t size,
                       uint8_t msg_type);

/**
 * Add an object to the RSVP message.
 */
int rsvp_builder_add_obj(struct rsvp_builder* b, uint8_t class_num,
                         uint8_t c_type, void* data, size_t data_len);

/* Helper functions for common objects */
int rsvp_builder_add_session_ipv4(struct rsvp_builder* b, struct in_addr* dest,
                                  uint16_t tunnel_id,
                                  struct in_addr* ext_tunnel_id);
int rsvp_builder_add_session_ipv6(struct rsvp_builder* b, struct in6_addr* dest,
                                  uint16_t tunnel_id,
                                  struct in6_addr* ext_tunnel_id);
int rsvp_builder_add_session_attribute(struct rsvp_builder* b,
                                       const char* name);
int rsvp_builder_add_hop_ipv4(struct rsvp_builder* b, struct in_addr* neighbor,
                              uint32_t logical_intf);
int rsvp_builder_add_hop_ipv6(struct rsvp_builder* b, struct in6_addr* neighbor,
                              uint32_t logical_intf);
int rsvp_builder_add_label_ipv4(struct rsvp_builder* b, uint32_t label);
int rsvp_builder_add_label_request(struct rsvp_builder* b, uint16_t l3pid);
int rsvp_builder_add_style(struct rsvp_builder* b, uint32_t style_val);
int rsvp_builder_add_time_values(struct rsvp_builder* b, uint32_t refresh_ms);
int rsvp_builder_add_tspec(struct rsvp_builder* b,
                           struct rsvp_sender_tspec* tspec);
int rsvp_builder_add_adspec(struct rsvp_builder* b, struct rsvp_adspec* adspec);

/**
 * Finalize the message (update lengths and checksum).
 */
size_t rsvp_builder_finalize(struct rsvp_builder* b);

uint16_t rsvp_checksum(const void* buf, size_t len);

#endif /* RSVP_BUILDER_H */
