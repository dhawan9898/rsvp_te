#include "rsvp_parser.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>

#include "rsvp_builder.h"

rsvp_error_t rsvp_parse_packet(const uint8_t* buffer, size_t len,
                               struct rsvp_message_info* info) {
    if (len < sizeof(struct iphdr)) {
        return RSVP_ERR_BUFFER_TOO_SMALL;
    }

    const struct iphdr* ip = (const struct iphdr*)buffer;
    size_t ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > len) {
        return RSVP_ERR_INVALID_PARAM;
    }

    if (len < ip_hdr_len + sizeof(struct rsvp_common_hdr)) {
        return RSVP_ERR_BUFFER_TOO_SMALL;
    }

    const struct rsvp_common_hdr* rsvp_hdr =
        (const struct rsvp_common_hdr*)(buffer + ip_hdr_len);
    size_t rsvp_len = ntohs(rsvp_hdr->length);
    if (rsvp_len < sizeof(struct rsvp_common_hdr)) {
        return RSVP_ERR_MALFORMED_OBJ;
    }
    if (ip_hdr_len + rsvp_len > len) {
        return RSVP_ERR_BUFFER_TOO_SMALL;
    }

    info->common_hdr = (struct rsvp_common_hdr*)rsvp_hdr; /* Cast away const for legacy compatibility */
    info->payload = (uint8_t*)(rsvp_hdr + 1);
    info->payload_len = rsvp_len - sizeof(struct rsvp_common_hdr);
    memset(info->lsp_name, 0, sizeof(info->lsp_name));

    /* Verify RSVP version */
    if ((rsvp_hdr->ver_flags >> 4) != RSVP_VERSION) {
        return RSVP_ERR_INVALID_PARAM;
    }

    /* Verify checksum non-destructively */
    uint16_t received_checksum = rsvp_hdr->checksum;
    if (received_checksum != 0) {
        uint8_t hdr_copy[sizeof(struct rsvp_common_hdr)];
        memcpy(hdr_copy, rsvp_hdr, sizeof(struct rsvp_common_hdr));
        struct rsvp_common_hdr* chdr = (struct rsvp_common_hdr*)hdr_copy;
        chdr->checksum = 0;

        /* Compute checksum over header (with checksum=0) and payload */
        /* rsvp_checksum is byte-order agnostic, but we need to combine its parts */
        
        /* Instead of re-implementing, let's use the buffer directly if possible, 
           but we need to zero out the checksum. Let's use a temporary buffer for the whole RSVP message 
           if it's small, or just do it in two parts if we want to be very efficient. */
        
        /* Efficiency: Calculate in two parts and merge */
        uint16_t h_cs = rsvp_checksum(hdr_copy, sizeof(struct rsvp_common_hdr));
        uint16_t p_cs = rsvp_checksum(info->payload, info->payload_len);
        
        /* Merging RFC 1071 checksums: sum of inverse, then inverse again */
        uint32_t combined = (uint32_t)ntohs(~h_cs) + (uint32_t)ntohs(~p_cs);
        while (combined >> 16) {
            combined = (combined & 0xffff) + (combined >> 16);
        }
        uint16_t computed_checksum = htons((uint16_t)(~combined));

        if (received_checksum != computed_checksum) {
            return RSVP_ERR_CHECKSUM;
        }
    }

    /* Strict parse to find objects */
    const uint8_t* obj_ptr = info->payload;
    size_t remaining = info->payload_len;

    while (remaining >= sizeof(struct rsvp_obj_hdr)) {
        const struct rsvp_obj_hdr* obj_hdr = (const struct rsvp_obj_hdr*)obj_ptr;
        size_t obj_len = ntohs(obj_hdr->length);

        if (obj_len < sizeof(struct rsvp_obj_hdr) || obj_len > remaining) {
            return RSVP_ERR_MALFORMED_OBJ; /* Object length invalid */
        }

        size_t aligned_obj_len = RSVP_ALIGN(obj_len);
        if (aligned_obj_len > remaining && aligned_obj_len != remaining + (remaining % 4 ? 4 - (remaining % 4) : 0)) {
            /* If it's the last object, the packet might not be perfectly padded to 4 bytes */
            /* But the object length itself shouldn't exceed remaining payload */
        }

        const uint8_t* obj_data = obj_ptr + sizeof(struct rsvp_obj_hdr);

        switch (obj_hdr->class_num) {
            case RSVP_CLASS_SESSION:
                if ((obj_hdr->c_type == 1 || obj_hdr->c_type == 7) &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_session_ipv4)) {
                    info->sess_v4 = (struct rsvp_session_ipv4*)obj_data;
                    memcpy(&info->key.session, info->sess_v4,
                           sizeof(struct rsvp_session_ipv4));
                } else if ((obj_hdr->c_type == 2 || obj_hdr->c_type == 8) &&
                           obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_session_ipv6)) {
                    info->sess_v6 = (struct rsvp_session_ipv6*)obj_data;
                }
                break;

            case RSVP_CLASS_HOP:
                if (obj_hdr->c_type == 1 &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_hop_ipv4)) {
                    info->hop_v4 = (struct rsvp_hop_ipv4*)obj_data;
                } else if (obj_hdr->c_type == 2 &&
                           obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_hop_ipv6)) {
                    info->hop_v6 = (struct rsvp_hop_ipv6*)obj_data;
                }
                break;

            case RSVP_CLASS_TIME_VALUES:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_time_values)) {
                    info->time_values = (struct rsvp_time_values*)obj_data;
                }
                break;

            case RSVP_CLASS_ERROR_SPEC:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_error_spec_ipv4)) {
                    info->error_spec = (struct rsvp_error_spec_ipv4*)obj_data;
                }
                break;

            case RSVP_CLASS_SENDER_TEMPLATE:
            case RSVP_CLASS_FILTER_SPEC:
                if ((obj_hdr->c_type == 1 || obj_hdr->c_type == 7) &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_sender_ipv4)) {
                    info->sender_v4 = (struct rsvp_sender_ipv4*)obj_data;
                    memcpy(&info->key.sender, info->sender_v4,
                           sizeof(struct rsvp_sender_ipv4));
                } else if ((obj_hdr->c_type == 2 || obj_hdr->c_type == 8) &&
                           obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_sender_ipv6)) {
                    info->sender_v6 = (struct rsvp_sender_ipv6*)obj_data;
                }
                break;

            case RSVP_CLASS_SENDER_TSPEC:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_sender_tspec)) {
                    info->tspec = (struct rsvp_sender_tspec*)obj_data;
                }
                break;

            case RSVP_CLASS_ADSPEC:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_adspec)) {
                    info->adspec = (struct rsvp_adspec*)obj_data;
                }
                break;

            case RSVP_CLASS_EXPLICIT_ROUTE:
                if (obj_len > sizeof(struct rsvp_obj_hdr)) {
                    info->ero = (struct rsvp_ero_ipv4_subobj*)obj_data;
                    info->ero_len = obj_len - sizeof(struct rsvp_obj_hdr);
                }
                break;

            case RSVP_CLASS_LABEL:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_label_ipv4)) {
                    info->label = (struct rsvp_label_ipv4*)obj_data;
                }
                break;

            case RSVP_CLASS_LABEL_REQUEST:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_label_request)) {
                    info->label_req = (struct rsvp_label_request*)obj_data;
                }
                break;

            case RSVP_CLASS_SESSION_ATTRIB:
                if (obj_hdr->c_type == 7 &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_session_attribute)) {
                    info->sess_attr = (struct rsvp_session_attribute*)obj_data;
                    if (info->sess_attr->name_length > 0 &&
                        sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_session_attribute) +
                                info->sess_attr->name_length <= obj_len) {
                        size_t nlen = info->sess_attr->name_length;
                        if (nlen >= sizeof(info->lsp_name))
                            nlen = sizeof(info->lsp_name) - 1;
                        memcpy(info->lsp_name, info->sess_attr->name, nlen);
                        info->lsp_name[nlen] = '\0';
                    }
                } else if (obj_hdr->c_type == 1 &&
                           obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_session_attribute_ra)) {
                    info->sess_attr_ra = (struct rsvp_session_attribute_ra*)obj_data;
                    if (info->sess_attr_ra->name_length > 0 &&
                        sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_session_attribute_ra) +
                                info->sess_attr_ra->name_length <= obj_len) {
                        size_t nlen = info->sess_attr_ra->name_length;
                        if (nlen >= sizeof(info->lsp_name))
                            nlen = sizeof(info->lsp_name) - 1;
                        memcpy(info->lsp_name, info->sess_attr_ra->name, nlen);
                        info->lsp_name[nlen] = '\0';
                    }
                }
                break;

            default:
                break;
        }

        /* Prevent infinite loop if aligned_obj_len is 0 (though we checked obj_len >= sizeof(hdr)) */
        if (aligned_obj_len == 0) break;
        if (aligned_obj_len > remaining) break;
        
        obj_ptr += aligned_obj_len;
        remaining -= aligned_obj_len;
    }

    /* Strict Validation for mandatory objects based on message type */
    switch (info->common_hdr->msg_type) {
        case RSVP_MSG_PATH:
            if (!info->sess_v4 && !info->sess_v6) return RSVP_ERR_MALFORMED_OBJ;
            if (!info->sender_v4 && !info->sender_v6) return RSVP_ERR_MALFORMED_OBJ;
            break;
        case RSVP_MSG_RESV:
            if (!info->sess_v4 && !info->sess_v6) return RSVP_ERR_MALFORMED_OBJ;
            if (!info->hop_v4 && !info->hop_v6) return RSVP_ERR_MALFORMED_OBJ;
            /* STYLE is mandatory in RESV */
            break;
        default:
            break;
    }

    return RSVP_SUCCESS;
}
