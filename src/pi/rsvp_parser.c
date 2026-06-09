#include "rsvp_parser.h"
#include "rsvp_builder.h"
#include <netinet/ip.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

int rsvp_parse_packet(uint8_t *buffer, size_t len, struct rsvp_message_info *info) {
    struct iphdr *ip = (struct iphdr *)buffer;
    size_t ip_hdr_len = ip->ihl * 4;

    if (len < ip_hdr_len + sizeof(struct rsvp_common_hdr)) {
        return -1;
    }

    struct rsvp_common_hdr *rsvp_hdr = (struct rsvp_common_hdr *)(buffer + ip_hdr_len);
    info->common_hdr = rsvp_hdr;
    info->payload = (uint8_t *)(rsvp_hdr + 1);
    info->payload_len = ntohs(rsvp_hdr->length) - sizeof(struct rsvp_common_hdr);

    /* Verify RSVP version */
    if ((rsvp_hdr->ver_flags >> 4) != 1) {
        return -1;
    }

    /* Verify checksum */
    uint16_t received_checksum = rsvp_hdr->checksum;
    rsvp_hdr->checksum = 0;
    uint16_t computed_checksum = rsvp_checksum((uint16_t *)rsvp_hdr, ntohs(rsvp_hdr->length) / 2);
    if (received_checksum != computed_checksum && received_checksum != 0) {
        rsvp_hdr->checksum = received_checksum;
        return -1; /* Checksum mismatch */
    }
    rsvp_hdr->checksum = received_checksum;

    /* Shallow parse to find objects */
    uint8_t *obj_ptr = info->payload;
    size_t remaining = info->payload_len;
    bool session_found = false;
    bool sender_found = false;

    while (remaining >= sizeof(struct rsvp_obj_hdr)) {
        struct rsvp_obj_hdr *obj_hdr = (struct rsvp_obj_hdr *)obj_ptr;
        size_t obj_len = ntohs(obj_hdr->length);

        if (obj_len < sizeof(struct rsvp_obj_hdr) || obj_len > remaining) {
            break;
        }

        uint8_t *obj_data = obj_ptr + sizeof(struct rsvp_obj_hdr);

        switch (obj_hdr->class_num) {
            case RSVP_CLASS_SESSION:
                if (obj_hdr->c_type == 1 || obj_hdr->c_type == 7) { /* IPv4 or IPv4 LSP */
                    info->sess_v4 = (struct rsvp_session_ipv4 *)obj_data;
                    memcpy(&info->key.session, info->sess_v4, sizeof(struct rsvp_session_ipv4));
                    session_found = true;
                } else if (obj_hdr->c_type == 2 || obj_hdr->c_type == 8) { /* IPv6 or IPv6 LSP */
                    info->sess_v6 = (struct rsvp_session_ipv6 *)obj_data;
                    /* TODO: Handle IPv6 key if needed */
                }
                break;

            case RSVP_CLASS_HOP:
                if (obj_hdr->c_type == 1) {
                    info->hop_v4 = (struct rsvp_hop_ipv4 *)obj_data;
                } else if (obj_hdr->c_type == 2) {
                    info->hop_v6 = (struct rsvp_hop_ipv6 *)obj_data;
                }
                break;

            case RSVP_CLASS_TIME_VALUES:
                info->time_values = (struct rsvp_time_values *)obj_data;
                break;

            case RSVP_CLASS_ERROR_SPEC:
                info->error_spec = (struct rsvp_error_spec_ipv4 *)obj_data;
                break;

            case RSVP_CLASS_SENDER_TEMPLATE:
            case RSVP_CLASS_FILTER_SPEC:
                if (obj_hdr->c_type == 1 || obj_hdr->c_type == 7) { /* IPv4 or IPv4 LSP */
                    info->sender_v4 = (struct rsvp_sender_ipv4 *)obj_data;
                    memcpy(&info->key.sender, info->sender_v4, sizeof(struct rsvp_sender_ipv4));
                    sender_found = true;
                } else if (obj_hdr->c_type == 2 || obj_hdr->c_type == 8) { /* IPv6 or IPv6 LSP */
                    info->sender_v6 = (struct rsvp_sender_ipv6 *)obj_data;
                }
                break;

            case RSVP_CLASS_SENDER_TSPEC:
                info->tspec = (struct rsvp_sender_tspec *)obj_data;
                break;

            case RSVP_CLASS_ADSPEC:
                info->adspec = (struct rsvp_adspec *)obj_data;
                break;

            case RSVP_CLASS_EXPLICIT_ROUTE:
                info->ero = (struct rsvp_ero_ipv4_subobj *)obj_data;
                info->ero_len = obj_len - sizeof(struct rsvp_obj_hdr);
                break;

            case RSVP_CLASS_LABEL:
                info->label = (struct rsvp_label_ipv4 *)obj_data;
                break;

            case RSVP_CLASS_LABEL_REQUEST:
                info->label_req = (struct rsvp_label_request *)obj_data;
                break;

            case RSVP_CLASS_SESSION_ATTRIB:
                if (obj_hdr->c_type == 1 || obj_hdr->c_type == 7) {
                    info->sess_attr = (struct rsvp_session_attribute *)obj_data;
                    if (info->sess_attr->name_length > 0) {
                        /* name_length is uint8_t, so it's always <= 255. lsp_name is 256 bytes. */
                        memcpy(info->lsp_name, info->sess_attr->name, info->sess_attr->name_length);
                        info->lsp_name[info->sess_attr->name_length] = '\0';
                    }
                }
                break;

            default:
                /* Unknown or unsupported object class */
                break;
        }

        obj_ptr += obj_len;
        remaining -= obj_len;
    }

    (void)session_found;
    (void)sender_found;

    return 0;
}
