#include "rsvp_builder.h"
#include <string.h>
#include <arpa/inet.h>

void rsvp_builder_init(struct rsvp_builder *b, uint8_t *buffer, size_t size, uint8_t msg_type) {
    b->buffer = buffer;
    b->size = size;
    b->offset = sizeof(struct rsvp_common_hdr);
    b->hdr = (struct rsvp_common_hdr *)buffer;

    memset(buffer, 0, size);
    b->hdr->ver_flags = (RSVP_VERSION << 4);
    b->hdr->msg_type = msg_type;
    b->hdr->ttl = 255;
}

int rsvp_builder_add_obj(struct rsvp_builder *b, uint8_t class_num, uint8_t c_type, void *data, size_t data_len) {
    size_t obj_total_len = sizeof(struct rsvp_obj_hdr) + data_len;
    
    if (b->offset + obj_total_len > b->size) {
        return -1;
    }

    struct rsvp_obj_hdr *obj_hdr = (struct rsvp_obj_hdr *)(b->buffer + b->offset);
    obj_hdr->length = htons(obj_total_len);
    obj_hdr->class_num = class_num;
    obj_hdr->c_type = c_type;

    memcpy(b->buffer + b->offset + sizeof(struct rsvp_obj_hdr), data, data_len);
    
    b->offset += RSVP_ALIGN(obj_total_len);
    return 0;
}

int rsvp_builder_add_session_ipv4(struct rsvp_builder *b, struct in_addr *dest, uint16_t tunnel_id, struct in_addr *ext_tunnel_id) {
    struct rsvp_session_ipv4 sess;
    memset(&sess, 0, sizeof(sess));
    sess.dest_addr = *dest;
    sess.tunnel_id = tunnel_id;
    sess.extended_tunnel_id = *ext_tunnel_id;
    return rsvp_builder_add_obj(b, RSVP_CLASS_SESSION, 1, &sess, sizeof(sess));
}

int rsvp_builder_add_session_ipv6(struct rsvp_builder *b, struct in6_addr *dest, uint16_t tunnel_id, struct in6_addr *ext_tunnel_id) {
    struct rsvp_session_ipv6 sess;
    memset(&sess, 0, sizeof(sess));
    sess.dest_addr = *dest;
    sess.tunnel_id = tunnel_id;
    sess.extended_tunnel_id = *ext_tunnel_id;
    return rsvp_builder_add_obj(b, RSVP_CLASS_SESSION, 2, &sess, sizeof(sess));
}

int rsvp_builder_add_hop_ipv4(struct rsvp_builder *b, struct in_addr *neighbor, uint32_t logical_intf) {
    struct rsvp_hop_ipv4 hop;
    memset(&hop, 0, sizeof(hop));
    hop.neighbor_addr = *neighbor;
    hop.logical_interface = logical_intf;
    return rsvp_builder_add_obj(b, RSVP_CLASS_HOP, 1, &hop, sizeof(hop));
}

int rsvp_builder_add_hop_ipv6(struct rsvp_builder *b, struct in6_addr *neighbor, uint32_t logical_intf) {
    struct rsvp_hop_ipv6 hop;
    memset(&hop, 0, sizeof(hop));
    hop.neighbor_addr = *neighbor;
    hop.logical_interface = logical_intf;
    return rsvp_builder_add_obj(b, RSVP_CLASS_HOP, 2, &hop, sizeof(hop));
}

int rsvp_builder_add_label_ipv4(struct rsvp_builder *b, uint32_t label) {
    struct rsvp_label_ipv4 lbl;
    lbl.label = htonl(label);
    return rsvp_builder_add_obj(b, RSVP_CLASS_LABEL, 1, &lbl, sizeof(lbl));
}

int rsvp_builder_add_time_values(struct rsvp_builder *b, uint32_t refresh_ms) {
    struct rsvp_time_values tv;
    tv.refresh_ms = htonl(refresh_ms);
    return rsvp_builder_add_obj(b, RSVP_CLASS_TIME_VALUES, 1, &tv, sizeof(tv));
}

int rsvp_builder_add_tspec(struct rsvp_builder *b, struct rsvp_sender_tspec *tspec) {
    return rsvp_builder_add_obj(b, RSVP_CLASS_SENDER_TSPEC, 2, tspec, sizeof(*tspec));
}

int rsvp_builder_add_adspec(struct rsvp_builder *b, struct rsvp_adspec *adspec) {
    return rsvp_builder_add_obj(b, RSVP_CLASS_ADSPEC, 2, adspec, sizeof(*adspec));
}

static uint16_t rsvp_checksum(uint16_t *buf, int nwords) {
    uint32_t sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

size_t rsvp_builder_finalize(struct rsvp_builder *b) {
    b->hdr->length = htons(b->offset);
    b->hdr->checksum = 0;
    
    /* Checksum is calculated over the entire RSVP message */
    b->hdr->checksum = rsvp_checksum((uint16_t *)b->buffer, b->offset / 2);
    
    return b->offset;
}
