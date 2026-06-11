#include "rsvp_builder.h"

#include <arpa/inet.h>
#include <string.h>

void rsvp_builder_init(struct rsvp_builder* b, uint8_t* buffer, size_t size,
                       uint8_t msg_type) {
    b->buffer = buffer;
    b->size = size;
    b->offset = sizeof(struct rsvp_common_hdr);
    b->hdr = (struct rsvp_common_hdr*)buffer;

    memset(buffer, 0, size);
    b->hdr->ver_flags = (RSVP_VERSION << 4);
    b->hdr->msg_type = msg_type;
    b->hdr->ttl = 255;
}

int rsvp_builder_add_obj(struct rsvp_builder* b, uint8_t class_num,
                         uint8_t c_type, void* data, size_t data_len) {
    size_t obj_total_len = sizeof(struct rsvp_obj_hdr) + data_len;
    size_t aligned_len = RSVP_ALIGN(obj_total_len);

    if (b->offset + aligned_len > b->size) {
        return -1;
    }

    struct rsvp_obj_hdr* obj_hdr =
        (struct rsvp_obj_hdr*)(b->buffer + b->offset);
    obj_hdr->length = htons(aligned_len);
    obj_hdr->class_num = class_num;
    obj_hdr->c_type = c_type;

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
    uint8_t buf[256] = {0};
    struct rsvp_session_attribute* attr = (struct rsvp_session_attribute*)buf;

    uint8_t name_len = name ? strlen(name) : 0;
    if (name_len > 200) name_len = 200; /* Safety limit */

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
    lbl.label = htonl(label << 12);
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

static uint32_t float_to_net(float value) {
    union un temp;
    temp.f = value;
    return htonl(temp.val);
}

static uint32_t net_to_float(uint32_t value) {
    union un temp;
    temp.val = ntohl(value);
    return temp.f;
}

int rsvp_builder_add_tspec(struct rsvp_builder* b,
                           struct rsvp_sender_tspec* tspec) {
    struct rsvp_sender_tspec wire_tspec;
    memcpy(&wire_tspec, tspec, sizeof(wire_tspec));
    wire_tspec.length = htons((sizeof(wire_tspec) / 4) - 1);
    wire_tspec.svc_length = htons(tspec->svc_length);
    wire_tspec.param_length = htons(tspec->param_length);

    uint32_t net_value;
    net_value = float_to_net(tspec->token_bucket_rate);
    memcpy(&wire_tspec.token_bucket_rate, &net_value, sizeof(net_value));
    net_value = float_to_net(tspec->token_bucket_size);
    memcpy(&wire_tspec.token_bucket_size, &net_value, sizeof(net_value));
    net_value = float_to_net(tspec->peak_data_rate);
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
    wire_tspec.length = htons((sizeof(wire_tspec) / 4) - 1);
    wire_tspec.svc_length = htons(tspec->svc_length);
    wire_tspec.param_length = htons(tspec->param_length);

    uint32_t net_value;
    net_value = float_to_net(tspec->token_bucket_rate);
    memcpy(&wire_tspec.token_bucket_rate, &net_value, sizeof(net_value));
    net_value = float_to_net(tspec->token_bucket_size);
    memcpy(&wire_tspec.token_bucket_size, &net_value, sizeof(net_value));
    net_value = float_to_net(tspec->peak_data_rate);
    memcpy(&wire_tspec.peak_data_rate, &net_value, sizeof(net_value));

    wire_tspec.min_policed_unit = htonl(tspec->min_policed_unit);
    wire_tspec.max_packet_size = htonl(tspec->max_packet_size);
    return rsvp_builder_add_obj(b, RSVP_CLASS_FLOWSPEC, 2, &wire_tspec,
                                sizeof(wire_tspec));
}

int rsvp_builder_add_adspec(struct rsvp_builder* b,
                            struct rsvp_adspec* adspec) {
    return rsvp_builder_add_obj(b, RSVP_CLASS_ADSPEC, 2, adspec,
                                sizeof(*adspec));
}

int rsvp_builder_add_adspec(struct rsvp_builder* b,
                            struct rsvp_adspec* adspec) {
    return rsvp_builder_add_obj(b, RSVP_CLASS_ADSPEC, 2, adspec,
                                sizeof(*adspec));
}

uint16_t rsvp_checksum(const void* buf, size_t len) {
    const uint8_t* data = (const uint8_t*)buf;
    uint32_t sum = 0;

    while (len > 1) {
        uint16_t word;
        memcpy(&word, data, sizeof(word));
        sum += ntohs(word);
        data += 2;
        len -= 2;
    }
    if (len == 1) {
        uint16_t word = data[0] << 8;
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return htons((uint16_t)(~sum));
}

size_t rsvp_builder_finalize(struct rsvp_builder* b) {
    b->hdr->length = htons(b->offset);
    b->hdr->checksum = 0;

    /* Checksum is calculated over the entire RSVP message */
    b->hdr->checksum = rsvp_checksum((uint16_t*)b->buffer, b->offset);

    return b->offset;
}
