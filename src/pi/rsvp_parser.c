#include "rsvp_parser.h"
#include "rsvp_builder.h"
#include <netinet/ip.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

int rsvp_parse_packet(uint8_t *buffer, size_t len, struct rsvp_message_info *info) {
    if (len < sizeof(struct iphdr)) {
        return -1;
    }

    struct iphdr *ip = (struct iphdr *)buffer;
    size_t ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > len) {
        return -1;
    }

    if (len < ip_hdr_len + sizeof(struct rsvp_common_hdr)) {
        return -1;
    }

    struct rsvp_common_hdr *rsvp_hdr = (struct rsvp_common_hdr *)(buffer + ip_hdr_len);
    size_t rsvp_len = ntohs(rsvp_hdr->length);
    if (rsvp_len < sizeof(struct rsvp_common_hdr)) {
        return -1;
    }
    if (ip_hdr_len + rsvp_len > len) {
        return -1;
    }

    info->common_hdr = rsvp_hdr;
    info->payload = (uint8_t *)(rsvp_hdr + 1);
    info->payload_len = rsvp_len - sizeof(struct rsvp_common_hdr);
    memset(info->lsp_name, 0, sizeof(info->lsp_name));

    /* Verify RSVP version */
    if ((rsvp_hdr->ver_flags >> 4) != RSVP_VERSION) {
        return -1;
    }

    /* Verify checksum */
    uint16_t received_checksum = rsvp_hdr->checksum;
    rsvp_hdr->checksum = 0;
    uint16_t computed_checksum = rsvp_checksum(rsvp_hdr, rsvp_len);
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

        size_t aligned_obj_len = RSVP_ALIGN(obj_len);
        if (aligned_obj_len > remaining) {
            break;
        }

        uint8_t *obj_data = obj_ptr + sizeof(struct rsvp_obj_hdr);

        switch (obj_hdr->class_num) {
            case RSVP_CLASS_SESSION:
                if ((obj_hdr->c_type == 1 || obj_hdr->c_type == 7) && obj_len >= sizeof(struct rsvp_session_ipv4)) {
                    info->sess_v4 = (struct rsvp_session_ipv4 *)obj_data;
                    memcpy(&info->key.session, info->sess_v4, sizeof(struct rsvp_session_ipv4));
                    session_found = true;
                } else if ((obj_hdr->c_type == 2 || obj_hdr->c_type == 8) && obj_len >= sizeof(struct rsvp_session_ipv6)) {
                    info->sess_v6 = (struct rsvp_session_ipv6 *)obj_data;
                    /* TODO: Handle IPv6 key if needed */
                }
                break;

            case RSVP_CLASS_HOP:
                if (obj_hdr->c_type == 1 && obj_len >= sizeof(struct rsvp_hop_ipv4)) {
                    info->hop_v4 = (struct rsvp_hop_ipv4 *)obj_data;
                } else if (obj_hdr->c_type == 2 && obj_len >= sizeof(struct rsvp_hop_ipv6)) {
                    info->hop_v6 = (struct rsvp_hop_ipv6 *)obj_data;
                }
                break;

            case RSVP_CLASS_TIME_VALUES:
                if (obj_len >= sizeof(struct rsvp_time_values)) {
                    info->time_values = (struct rsvp_time_values *)obj_data;
                }
                break;

            case RSVP_CLASS_ERROR_SPEC:
                if (obj_len >= sizeof(struct rsvp_error_spec_ipv4)) {
                    info->error_spec = (struct rsvp_error_spec_ipv4 *)obj_data;
                }
                break;

            case RSVP_CLASS_SENDER_TEMPLATE:
            case RSVP_CLASS_FILTER_SPEC:
                if ((obj_hdr->c_type == 1 || obj_hdr->c_type == 7) && obj_len >= sizeof(struct rsvp_sender_ipv4)) {
                    info->sender_v4 = (struct rsvp_sender_ipv4 *)obj_data;
                    memcpy(&info->key.sender, info->sender_v4, sizeof(struct rsvp_sender_ipv4));
                    sender_found = true;
                } else if ((obj_hdr->c_type == 2 || obj_hdr->c_type == 8) && obj_len >= sizeof(struct rsvp_sender_ipv6)) {
                    info->sender_v6 = (struct rsvp_sender_ipv6 *)obj_data;
                }
                break;

            case RSVP_CLASS_SENDER_TSPEC:
                if (obj_len >= sizeof(struct rsvp_sender_tspec)) {
                    info->tspec = (struct rsvp_sender_tspec *)obj_data;
                }
                break;

            case RSVP_CLASS_ADSPEC:
                if (obj_len >= sizeof(struct rsvp_adspec)) {
                    info->adspec = (struct rsvp_adspec *)obj_data;
                }
                break;

            case RSVP_CLASS_EXPLICIT_ROUTE:
                if (obj_len > sizeof(struct rsvp_obj_hdr)) {
                    info->ero = (struct rsvp_ero_ipv4_subobj *)obj_data;
                    info->ero_len = obj_len - sizeof(struct rsvp_obj_hdr);
                }
                break;

            case RSVP_CLASS_LABEL:
                if (obj_len >= sizeof(struct rsvp_label_ipv4)) {
                    info->label = (struct rsvp_label_ipv4 *)obj_data;
                }
                break;

            case RSVP_CLASS_LABEL_REQUEST:
                if (obj_len >= sizeof(struct rsvp_label_request)) {
                    info->label_req = (struct rsvp_label_request *)obj_data;
                }
                break;

            case RSVP_CLASS_SESSION_ATTRIB:
                if (obj_hdr->c_type == 7 && obj_len >= sizeof(struct rsvp_session_attribute)) {
                    info->sess_attr = (struct rsvp_session_attribute *)obj_data;
                    if (info->sess_attr->name_length > 0 && 
                        sizeof(struct rsvp_session_attribute) + info->sess_attr->name_length <= (obj_len - sizeof(struct rsvp_obj_hdr))) {
                        size_t nlen = info->sess_attr->name_length;
                        if (nlen >= sizeof(info->lsp_name)) nlen = sizeof(info->lsp_name) - 1;
                        memcpy(info->lsp_name, info->sess_attr->name, nlen);
                        info->lsp_name[nlen] = '\0';
                    }
                } else if (obj_hdr->c_type == 1 && obj_len >= sizeof(struct rsvp_session_attribute_ra)) {
                    info->sess_attr_ra = (struct rsvp_session_attribute_ra *)obj_data;
                    if (info->sess_attr_ra->name_length > 0 && 
                        sizeof(struct rsvp_session_attribute_ra) + info->sess_attr_ra->name_length <= (obj_len - sizeof(struct rsvp_obj_hdr))) {
                        size_t nlen = info->sess_attr_ra->name_length;
                        if (nlen >= sizeof(info->lsp_name)) nlen = sizeof(info->lsp_name) - 1;
                        memcpy(info->lsp_name, info->sess_attr_ra->name, nlen);
                        info->lsp_name[nlen] = '\0';
                    }
                }
                break;

            default:
                break;
        }

        obj_ptr += aligned_obj_len;
        remaining -= aligned_obj_len;
    }

    (void)session_found;
    (void)sender_found;

    return 0;
}
