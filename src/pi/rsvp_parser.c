#include "rsvp_parser.h"
#include "common/rsvp_log.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>

#include "rsvp_builder.h"

rsvp_error_t rsvp_parse_packet(const uint8_t* buffer, size_t len,
                               struct rsvp_message_info* info) {
    LOG_DEBUG("Parser: Starting RSVP packet parsing (Length: %zu)", len);

    if (len < sizeof(struct iphdr)) {
        LOG_WARN("Parser: Packet too small for IP header");
        return RSVP_ERR_BUFFER_TOO_SMALL;
    }

    const struct iphdr* ip = (const struct iphdr*)buffer;
    size_t ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || ip_hdr_len > len) {
        LOG_WARN("Parser: Invalid IP header length: %zu", ip_hdr_len);
        return RSVP_ERR_INVALID_PARAM;
    }

    info->src_ip.s_addr = ip->saddr;
    info->dst_ip.s_addr = ip->daddr;

    if (len < ip_hdr_len + sizeof(struct rsvp_common_hdr)) {
        LOG_WARN("Parser: Packet too small for RSVP common header");
        return RSVP_ERR_BUFFER_TOO_SMALL;
    }

    const struct rsvp_common_hdr* rsvp_hdr =
        (const struct rsvp_common_hdr*)(buffer + ip_hdr_len);
    size_t rsvp_len = ntohs(rsvp_hdr->length);
    
    LOG_DEBUG("Parser: RSVP Header [Ver: %d, Type: %d, Flags: 0x%x, Length: %zu, TTL: %d]",
              rsvp_hdr->ver_flags >> 4, rsvp_hdr->msg_type, rsvp_hdr->ver_flags & 0x0F,
              rsvp_len, rsvp_hdr->ttl);

    if (rsvp_len < sizeof(struct rsvp_common_hdr)) {
        LOG_WARN("Parser: RSVP length field too small: %zu", rsvp_len);
        return RSVP_ERR_MALFORMED_OBJ;
    }
    if (ip_hdr_len + rsvp_len > len) {
        LOG_WARN("Parser: RSVP length (%zu) exceeds IP payload", rsvp_len);
        return RSVP_ERR_BUFFER_TOO_SMALL;
    }

    info->common_hdr = (struct rsvp_common_hdr*)rsvp_hdr; 
    info->payload = (uint8_t*)(rsvp_hdr + 1);
    info->payload_len = rsvp_len - sizeof(struct rsvp_common_hdr);
    memset(info->lsp_name, 0, sizeof(info->lsp_name));

    /* Verify RSVP version */
    if ((rsvp_hdr->ver_flags >> 4) != RSVP_VERSION) {
        LOG_WARN("Parser: Unsupported RSVP version: %d", rsvp_hdr->ver_flags >> 4);
        return RSVP_ERR_INVALID_PARAM;
    }

    /* Verify checksum non-destructively */
    uint16_t received_checksum = rsvp_hdr->checksum;
    if (received_checksum != 0) {
        uint8_t hdr_copy[sizeof(struct rsvp_common_hdr)];
        memcpy(hdr_copy, rsvp_hdr, sizeof(struct rsvp_common_hdr));
        struct rsvp_common_hdr* chdr = (struct rsvp_common_hdr*)hdr_copy;
        chdr->checksum = 0;

        uint16_t h_cs = rsvp_checksum(hdr_copy, sizeof(struct rsvp_common_hdr));
        uint16_t p_cs = rsvp_checksum(info->payload, info->payload_len);
        
        uint32_t combined = (uint32_t)ntohs(~h_cs) + (uint32_t)ntohs(~p_cs);
        while (combined >> 16) {
            combined = (combined & 0xffff) + (combined >> 16);
        }
        uint16_t computed_checksum = htons((uint16_t)(~combined));

        if (received_checksum != computed_checksum) {
            LOG_WARN("Parser: Checksum FAILED! (Received: 0x%x, Computed: 0x%x)", 
                     received_checksum, computed_checksum);
            return RSVP_ERR_CHECKSUM;
        }
        LOG_DEBUG("Parser: Checksum OK");
    }

    /* Strict parse to find objects */
    const uint8_t* obj_ptr = info->payload;
    size_t remaining = info->payload_len;

    while (remaining >= sizeof(struct rsvp_obj_hdr)) {
        const struct rsvp_obj_hdr* obj_hdr = (const struct rsvp_obj_hdr*)obj_ptr;
        size_t obj_len = ntohs(obj_hdr->length);

        LOG_DEBUG("Parser: Found Object [Class: %d, C-Type: %d, Length: %zu]",
                  obj_hdr->class_num, obj_hdr->c_type, obj_len);

        if (obj_len < sizeof(struct rsvp_obj_hdr) || obj_len > remaining) {
            LOG_WARN("Parser: Invalid object length: %zu (Remaining: %zu)", obj_len, remaining);
            return RSVP_ERR_MALFORMED_OBJ; 
        }

        size_t aligned_obj_len = RSVP_ALIGN(obj_len);
        const uint8_t* obj_data = obj_ptr + sizeof(struct rsvp_obj_hdr);

        switch (obj_hdr->class_num) {
            case RSVP_CLASS_SESSION:
                if ((obj_hdr->c_type == 1 || obj_hdr->c_type == 7) &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_session_ipv4)) {
                    info->sess_v4 = (struct rsvp_session_ipv4*)obj_data;
                    memcpy(&info->key.session, info->sess_v4, sizeof(struct rsvp_session_ipv4));
                    char dest_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &info->sess_v4->dest_addr, dest_str, sizeof(dest_str));
                    LOG_DEBUG("  - SESSION IPv4: Dest %s, TunnelID %d", dest_str, ntohs(info->sess_v4->tunnel_id));
                }
                break;

            case RSVP_CLASS_HOP:
                if (obj_hdr->c_type == 1 &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_hop_ipv4)) {
                    info->hop_v4 = (struct rsvp_hop_ipv4*)obj_data;
                    char hop_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &info->hop_v4->neighbor_addr, hop_str, sizeof(hop_str));
                    LOG_DEBUG("  - HOP IPv4: Neighbor %s, IfIndex %u", hop_str, ntohl(info->hop_v4->logical_interface));
                }
                break;

            case RSVP_CLASS_TIME_VALUES:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_time_values)) {
                    info->time_values = (struct rsvp_time_values*)obj_data;
                    LOG_DEBUG("  - TIME VALUES: Refresh %u ms", ntohl(info->time_values->refresh_ms));
                }
                break;

            case RSVP_CLASS_ERROR_SPEC:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_error_spec_ipv4)) {
                    info->error_spec = (struct rsvp_error_spec_ipv4*)obj_data;
                    char node_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &info->error_spec->error_node, node_str, sizeof(node_str));
                    LOG_DEBUG("  - ERROR SPEC: Code %d, Value %d, Node %s", 
                              info->error_spec->error_code, info->error_spec->error_value, node_str);
                }
                break;

            case RSVP_CLASS_SENDER_TEMPLATE:
            case RSVP_CLASS_FILTER_SPEC:
                if ((obj_hdr->c_type == 1 || obj_hdr->c_type == 7) &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_sender_ipv4)) {
                    info->sender_v4 = (struct rsvp_sender_ipv4*)obj_data;
                    memcpy(&info->key.sender, info->sender_v4, sizeof(struct rsvp_sender_ipv4));
                    char src_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &info->sender_v4->source_addr, src_str, sizeof(src_str));
                    LOG_DEBUG("  - SENDER/FILTER IPv4: Source %s, LSP-ID %d", src_str, ntohs(info->sender_v4->lsp_id));
                }
                break;

            case RSVP_CLASS_LABEL:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_label_ipv4)) {
                    info->label = (struct rsvp_label_ipv4*)obj_data;
                    LOG_DEBUG("  - LABEL: %u", ntohl(info->label->label) >> 12);
                }
                break;

            case RSVP_CLASS_LABEL_REQUEST:
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_label_request)) {
                    info->label_req = (struct rsvp_label_request*)obj_data;
                    LOG_DEBUG("  - LABEL REQUEST: L3PID 0x%04x", ntohs(info->label_req->l3pid));
                }
                break;

            case RSVP_CLASS_SESSION_ATTRIB:
                if (obj_hdr->c_type == 7 &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_session_attribute)) {
                    info->sess_attr = (struct rsvp_session_attribute*)obj_data;
                    if (info->sess_attr->name_length > 0) {
                        size_t nlen = info->sess_attr->name_length;
                        if (nlen >= sizeof(info->lsp_name)) nlen = sizeof(info->lsp_name) - 1;
                        memcpy(info->lsp_name, info->sess_attr->name, nlen);
                        info->lsp_name[nlen] = '\0';
                        LOG_DEBUG("  - SESSION ATTRIB: Name %s", info->lsp_name);
                    }
                }
                break;

            default:
                LOG_DEBUG("  - Unhandled object class %d", obj_hdr->class_num);
                break;
        }

        if (aligned_obj_len == 0) break;
        if (aligned_obj_len > remaining) break;
        
        obj_ptr += aligned_obj_len;
        remaining -= aligned_obj_len;
    }

    /* Strict Validation for mandatory objects based on message type */
    switch (info->common_hdr->msg_type) {
        case RSVP_MSG_PATH:
            if (!info->sess_v4 && !info->sess_v6) {
                LOG_WARN("Parser: PATH missing mandatory SESSION object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            if (!info->sender_v4 && !info->sender_v6) {
                LOG_WARN("Parser: PATH missing mandatory SENDER_TEMPLATE object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            break;
        case RSVP_MSG_RESV:
            if (!info->sess_v4 && !info->sess_v6) {
                LOG_WARN("Parser: RESV missing mandatory SESSION object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            if (!info->hop_v4 && !info->hop_v6) {
                LOG_WARN("Parser: RESV missing mandatory RSVP_HOP object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            break;
        case RSVP_MSG_PATHERR:
            if (!info->sess_v4 && !info->sess_v6) {
                LOG_WARN("Parser: PATHERR missing mandatory SESSION object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            if (!info->error_spec) {
                LOG_WARN("Parser: PATHERR missing mandatory ERROR_SPEC object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            break;
        case RSVP_MSG_RESVERR:
            if (!info->sess_v4 && !info->sess_v6) {
                LOG_WARN("Parser: RESVERR missing mandatory SESSION object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            if (!info->error_spec) {
                LOG_WARN("Parser: RESVERR missing mandatory ERROR_SPEC object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            break;
        case RSVP_MSG_PATHTEAR:
            if (!info->sess_v4 && !info->sess_v6) {
                LOG_WARN("Parser: PATHTEAR missing mandatory SESSION object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            if (!info->sender_v4 && !info->sender_v6) {
                LOG_WARN("Parser: PATHTEAR missing mandatory SENDER_TEMPLATE object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            break;
        case RSVP_MSG_RESVTEAR:
            if (!info->sess_v4 && !info->sess_v6) {
                LOG_WARN("Parser: RESVTEAR missing mandatory SESSION object");
                return RSVP_ERR_MALFORMED_OBJ;
            }
            break;
        default:
            LOG_DEBUG("Parser: Skipping validation for message type %d", info->common_hdr->msg_type);
            break;
    }

    LOG_DEBUG("Parser: Parse SUCCESS");
    return RSVP_SUCCESS;
}
