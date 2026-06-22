/**
 * @file rsvp_builder.c
 * @brief RSVP Message Builder Implementation.
 * @details Implements the functions to incrementally construct an RSVP-TE message, manage its buffer, and calculate the checksum.
 */

#include "rsvp_builder.h"
#include "common/rsvp_log.h"
#include "common/rsvp_error.h"
#include <arpa/inet.h>
#include <endian.h>
#include <string.h>

void rsvp_builder_init(struct rsvp_builder* b, uint8_t* buffer, size_t size,
                       uint8_t msg_type) {
    LOG_DEBUG("Builder: Initializing for Message Type %d (Buffer Size: %zu)", msg_type, size);
    
    /* Initialize builder structure fields */
    b->buffer = buffer;
    b->size = size;
    b->offset = sizeof(struct rsvp_common_hdr);
    b->hdr = (struct rsvp_common_hdr*)buffer;

    /* Zero out the buffer and set the common header fields */
    memset(buffer, 0, size);
    b->hdr->ver_flags = (RSVP_VERSION << 4);
    b->hdr->msg_type = msg_type;
    b->hdr->ttl = 255;
}

int rsvp_builder_add_obj(struct rsvp_builder* b, uint8_t class_num,
                         uint8_t c_type, void* data, size_t data_len) {
    /* Calculate the total object length including the RSVP object header */
    size_t obj_total_len = sizeof(struct rsvp_obj_hdr) + data_len;
    /* Ensure the length is 4-byte aligned as required by RFC 2205 */
    size_t aligned_len = RSVP_ALIGN(obj_total_len);

    LOG_DEBUG("Builder: Adding Object [Class: %d, C-Type: %d, DataLen: %zu, Aligned: %zu]",
              class_num, c_type, data_len, aligned_len);

    /* Verify that the new object fits within the remaining buffer space */
    if (b->offset + aligned_len > b->size) {
        LOG_ERROR("Builder: Buffer overflow when adding object class %d", class_num);
        return -1;
    }

    /* Populate the RSVP object header */
    struct rsvp_obj_hdr* obj_hdr =
        (struct rsvp_obj_hdr*)(b->buffer + b->offset);
    obj_hdr->length = htons(aligned_len);
    obj_hdr->class_num = class_num;
    obj_hdr->c_type = c_type;

    /* Copy the actual object payload into the buffer */
    memcpy(b->buffer + b->offset + sizeof(struct rsvp_obj_hdr), data, data_len);

    b->offset += aligned_len;
    return 0;
}

int rsvp_builder_add_session_ipv4(struct rsvp_builder* b, struct in_addr* dest,
                                  uint16_t tunnel_id,
                                  struct in_addr* ext_tunnel_id) {
    struct rsvp_session_ipv4 sess;
    memset(&sess, 0, sizeof(sess));
    sess.dest_addr = *dest;
    sess.tunnel_id = htons(tunnel_id);
    sess.extended_tunnel_id = *ext_tunnel_id;
    return rsvp_builder_add_obj(b, RSVP_CLASS_SESSION, 7, &sess, sizeof(sess));
}

int rsvp_builder_add_session_ipv6(struct rsvp_builder* b, struct in6_addr* dest,
                                  uint16_t tunnel_id,
                                  struct in6_addr* ext_tunnel_id) {
    struct rsvp_session_ipv6 sess;
    memset(&sess, 0, sizeof(sess));
    sess.dest_addr = *dest;
    sess.tunnel_id = htons(tunnel_id);
    sess.extended_tunnel_id = *ext_tunnel_id;
    return rsvp_builder_add_obj(b, RSVP_CLASS_SESSION, 8, &sess, sizeof(sess));
}

int rsvp_builder_add_session_attribute(struct rsvp_builder* b,
                                       const char* name) {
    uint8_t buf[300] = {0};
    struct rsvp_session_attribute* attr = (struct rsvp_session_attribute*)buf;

    /* Validate and optionally truncate the session name length */
    size_t name_len_full = name ? strlen(name) : 0;
    uint8_t name_len = (name_len_full > 255) ? 255 : (uint8_t)name_len_full;

    attr->setup_prio = 0;   /* Wireshark shows SetupPrio 0 */
    attr->holding_prio = 0; /* Wireshark shows HoldPrio 0 */
    attr->flags = 0x04;     /* Wireshark shows SE Style flag 0x04 */
    attr->name_length = name_len;

    if (name_len > 0) {
        memcpy(attr->name, name, name_len);
    }

    size_t obj_len = sizeof(struct rsvp_session_attribute) + name_len;
    return rsvp_builder_add_obj(b, RSVP_CLASS_SESSION_ATTRIB, 7, attr, obj_len);
}

int rsvp_builder_add_hop_ipv4(struct rsvp_builder* b, struct in_addr* neighbor,
                              uint32_t logical_intf) {
    struct rsvp_hop_ipv4 hop;
    memset(&hop, 0, sizeof(hop));
    hop.neighbor_addr = *neighbor;
    hop.logical_interface = htonl(logical_intf);
    return rsvp_builder_add_obj(b, RSVP_CLASS_HOP, 1, &hop, sizeof(hop));
}

int rsvp_builder_add_hop_ipv6(struct rsvp_builder* b, struct in6_addr* neighbor,
                              uint32_t logical_intf) {
    struct rsvp_hop_ipv6 hop;
    memset(&hop, 0, sizeof(hop));
    hop.neighbor_addr = *neighbor;
    hop.logical_interface = htonl(logical_intf);
    return rsvp_builder_add_obj(b, RSVP_CLASS_HOP, 2, &hop, sizeof(hop));
}

int rsvp_builder_add_label_ipv4(struct rsvp_builder* b, uint32_t label) {
    struct rsvp_label_ipv4 lbl;
    lbl.label = htonl(label);
    return rsvp_builder_add_obj(b, RSVP_CLASS_LABEL, 1, &lbl, sizeof(lbl));
}

int rsvp_builder_add_label_request(struct rsvp_builder* b, uint16_t l3pid) {
    struct rsvp_label_request req;
    req.reserved = 0;
    req.l3pid = htons(l3pid);
    return rsvp_builder_add_obj(b, RSVP_CLASS_LABEL_REQUEST, 1, &req,
                                sizeof(req));
}

int rsvp_builder_add_style(struct rsvp_builder* b, uint32_t style_val) {
    struct rsvp_style style;
    style.style = htonl(style_val);
    return rsvp_builder_add_obj(b, RSVP_CLASS_STYLE, 1, &style, sizeof(style));
}

int rsvp_builder_add_time_values(struct rsvp_builder* b, uint32_t refresh_ms) {
    struct rsvp_time_values tv;
    tv.refresh_ms = htonl(refresh_ms);
    return rsvp_builder_add_obj(b, RSVP_CLASS_TIME_VALUES, 1, &tv, sizeof(tv));
}

union net_un {
    uint32_t val;
    float f;
};

/**
 * @brief Convert a float to network byte order.
 */
uint32_t rsvp_float_to_net(float value) {
    union net_un temp;
    temp.f = value;
    return htonl(temp.val);
}

/**
 * @brief Convert a network byte order uint32_t (representing float) to host float.
 */
float rsvp_net_to_float(uint32_t net_value) {
    union net_un temp;
    temp.val = ntohl(net_value);
    return temp.f;
}

int rsvp_builder_add_tspec(struct rsvp_builder* b,
                           struct rsvp_sender_tspec* tspec) {
    struct rsvp_sender_tspec wire_tspec;
    memcpy(&wire_tspec, tspec, sizeof(wire_tspec));
    
    /* Convert TSpec fields to network byte order */
    wire_tspec.length = htons((sizeof(wire_tspec) / 4) - 1);
    wire_tspec.svc_length = htons(tspec->svc_length);
    wire_tspec.param_length = htons(tspec->param_length);

    uint32_t net_value;
    net_value = rsvp_float_to_net(tspec->token_bucket_rate);
    memcpy(&wire_tspec.token_bucket_rate, &net_value, sizeof(net_value));
    net_value = rsvp_float_to_net(tspec->token_bucket_size);
    memcpy(&wire_tspec.token_bucket_size, &net_value, sizeof(net_value));
    net_value = rsvp_float_to_net(tspec->peak_data_rate);
    memcpy(&wire_tspec.peak_data_rate, &net_value, sizeof(net_value));

    wire_tspec.min_policed_unit = htonl(tspec->min_policed_unit);
    wire_tspec.max_packet_size = htonl(tspec->max_packet_size);
    return rsvp_builder_add_obj(b, RSVP_CLASS_SENDER_TSPEC, 2, &wire_tspec,
                                sizeof(wire_tspec));
}

int rsvp_builder_add_flowspec(struct rsvp_builder* b,
                           struct rsvp_sender_tspec* tspec) {
    struct rsvp_sender_tspec wire_tspec;
    memcpy(&wire_tspec, tspec, sizeof(wire_tspec));
    
    /* Convert Flowspec fields to network byte order (shares TSpec structure) */
    wire_tspec.length = htons((sizeof(wire_tspec) / 4) - 1);
    wire_tspec.svc_length = htons(tspec->svc_length);
    wire_tspec.param_length = htons(tspec->param_length);

    uint32_t net_value;
    net_value = rsvp_float_to_net(tspec->token_bucket_rate);
    memcpy(&wire_tspec.token_bucket_rate, &net_value, sizeof(net_value));
    net_value = rsvp_float_to_net(tspec->token_bucket_size);
    memcpy(&wire_tspec.token_bucket_size, &net_value, sizeof(net_value));
    net_value = rsvp_float_to_net(tspec->peak_data_rate);
    memcpy(&wire_tspec.peak_data_rate, &net_value, sizeof(net_value));

    wire_tspec.min_policed_unit = htonl(tspec->min_policed_unit);
    wire_tspec.max_packet_size = htonl(tspec->max_packet_size);
    return rsvp_builder_add_obj(b, RSVP_CLASS_FLOWSPEC, 2, &wire_tspec,
                                sizeof(wire_tspec));
}

int rsvp_builder_add_ero(struct rsvp_builder* b, struct rsvp_ero_ipv4_subobj* ero_list, size_t count) {
    if (!b || !ero_list || count == 0) return RSVP_ERR_INVALID_PARAM;
    size_t obj_len = count * sizeof(struct rsvp_ero_ipv4_subobj);
    return rsvp_builder_add_obj(b, RSVP_CLASS_EXPLICIT_ROUTE, 1, ero_list, obj_len);
}

int rsvp_builder_add_rro(struct rsvp_builder* b, struct rsvp_ero_ipv4_subobj* rro_list, size_t count) {
    if (!b || !rro_list || count == 0) return RSVP_ERR_INVALID_PARAM;
    size_t obj_len = count * sizeof(struct rsvp_ero_ipv4_subobj);
    /* C-Type 1 for IPv4 RRO (RFC 3209) */
    return rsvp_builder_add_obj(b, RSVP_CLASS_RECORD_ROUTE, 1, rro_list, obj_len);
}

size_t rsvp_builder_add_integrity(struct rsvp_builder* b, uint8_t flags, uint8_t* key_id, uint64_t sequence_number, uint8_t* digest, size_t digest_len) {
    if (!b || !key_id || (!digest && digest_len > 0)) return 0;
    
    struct rsvp_integrity* int_obj;
    size_t obj_len = sizeof(struct rsvp_integrity) + digest_len;
    
    uint8_t buffer[256];
    if (obj_len > sizeof(buffer)) return 0; /* Simplify for now */
    
    int_obj = (struct rsvp_integrity*)buffer;
    int_obj->flags = flags;
    int_obj->reserved = 0;
    memcpy(int_obj->key_id, key_id, 6);
    int_obj->sequence_number = htobe64(sequence_number);
    if (digest_len > 0) {
        memcpy(int_obj->digest, digest, digest_len);
    }
    
    return rsvp_builder_add_obj(b, RSVP_CLASS_INTEGRITY, 1, int_obj, obj_len);
}

uint16_t rsvp_checksum(const void* buf, size_t len) {
    const uint16_t* ptr = (const uint16_t*)buf;
    uint32_t sum = 0;

    /* Compute the 16-bit one's complement sum */
    while (len > 1) {
        sum += ntohs(*ptr++);
        len -= 2;
    }

    /* Add left-over byte, if any */
    if (len > 0) {
        sum += (*(const uint8_t*)ptr) << 8;
    }

    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    /* Return the one's complement of the sum */
    return htons((uint16_t)(~sum));
}

int rsvp_checksum_verify(const void* buf, size_t len) {
    if (len < 4) return -1;
    
    const uint16_t* ptr = (const uint16_t*)buf;
    uint32_t sum = 0;
    size_t remaining = len;

    /* Sum everything except the checksum field at offset 2 */
    /* First 2 bytes (ver_flags and msg_type) */
    sum += ntohs(*ptr++);
    remaining -= 2;

    /* Skip checksum field */
    ptr++;
    remaining -= 2;

    /* Sum the rest */
    while (remaining > 1) {
        sum += ntohs(*ptr++);
        remaining -= 2;
    }

    if (remaining > 0) {
        sum += (*(const uint8_t*)ptr) << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    uint16_t computed = htons((uint16_t)(~sum));
    const struct rsvp_common_hdr* hdr = (const struct rsvp_common_hdr*)buf;
    
    return (hdr->checksum == computed) ? 0 : -1;
}

size_t rsvp_builder_finalize(struct rsvp_builder* b) {
    /* Update message length in the header */
    b->hdr->length = htons(b->offset);
    b->hdr->checksum = 0;

    /* Checksum is calculated over the entire RSVP message including header and all objects */
    b->hdr->checksum = rsvp_checksum((uint16_t*)b->buffer, b->offset);

    LOG_DEBUG("Builder: Finalized message [Type: %d, Length: %d, Checksum: 0x%04x]",
              b->hdr->msg_type, b->offset, ntohs(b->hdr->checksum));

    return b->offset;
}
