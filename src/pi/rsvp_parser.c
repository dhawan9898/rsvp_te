/**
 * @file rsvp_parser.c
 * @brief RSVP Packet Parser Implementation.
 * @details Implements the logic to parse raw RSVP packets, validate checksums,
 *           and extract objects according to RFC 2205.
 */

#include "rsvp_parser.h"
#include "common/rsvp_log.h"
#include <arpa/inet.h>
#include <endian.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>

#include "rsvp_builder.h"

rsvp_error_t rsvp_parse_packet(const uint8_t* buffer, size_t len,
                               struct rsvp_message_info* info) {
    LOG_DEBUG("Parser: Starting RSVP packet parsing (Length: %zu)", len);

    if (!info) return RSVP_ERR_INVALID_PARAM;
    memset(info, 0, sizeof(struct rsvp_message_info));

    /* Validate the overall length is at least the size of an IP header */
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

    /* Validate the length contains both IP and RSVP headers */
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

    /* Verify RSVP version */
    if ((rsvp_hdr->ver_flags >> 4) != RSVP_VERSION) {
        LOG_WARN("Parser: Unsupported RSVP version: %d", rsvp_hdr->ver_flags >> 4);
        return RSVP_ERR_INVALID_PARAM;
    }

    /* Verify RSVP checksum over the entire RSVP message without mutating the buffer */
    if (rsvp_hdr->checksum != 0) {
        if (rsvp_checksum_verify(rsvp_hdr, rsvp_len) != 0) {
            LOG_WARN("Parser: Checksum FAILED!");
            return RSVP_ERR_CHECKSUM;
        }
        LOG_DEBUG("Parser: Checksum OK");
    }

    /* Strict parse to find objects */
    const uint8_t* obj_ptr = info->payload;
    size_t remaining = info->payload_len;

    /* Loop through the remaining payload and extract supported objects */
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
            case RSVP_CLASS_INTEGRITY:
                if (info->integrity) break;
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_integrity)) {
                    info->integrity = (struct rsvp_integrity*)obj_data;
                    LOG_DEBUG("  - INTEGRITY: SeqNum %llu", (unsigned long long)be64toh(info->integrity->sequence_number));
                }
                break;

            case RSVP_CLASS_SESSION:
                if (info->sess_v4) break;
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
                if (info->hop_v4) break;
                if (obj_hdr->c_type == 1 &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_hop_ipv4)) {
                    info->hop_v4 = (struct rsvp_hop_ipv4*)obj_data;
                    char hop_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &info->hop_v4->neighbor_addr, hop_str, sizeof(hop_str));
                    LOG_DEBUG("  - HOP IPv4: Neighbor %s, IfIndex %u", hop_str, ntohl(info->hop_v4->logical_interface));
                }
                break;

            case RSVP_CLASS_TIME_VALUES:
                if (info->time_values) break;
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_time_values)) {
                    info->time_values = (struct rsvp_time_values*)obj_data;
                    LOG_DEBUG("  - TIME VALUES: Refresh %u ms", ntohl(info->time_values->refresh_ms));
                }
                break;

            case RSVP_CLASS_STYLE:
                if (info->style) break;
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_style)) {
                    info->style = (struct rsvp_style*)obj_data;
                    LOG_DEBUG("  - STYLE: %u", ntohl(info->style->style) & 0xFF);
                }
                break;

            case RSVP_CLASS_FLOWSPEC:
                if (info->flowspec) break;
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_sender_tspec)) {
                    info->flowspec = (struct rsvp_sender_tspec*)obj_data;
                    LOG_DEBUG("  - FLOWSPEC: Rate %.2f, Size %.2f",
                              info->flowspec->token_bucket_rate, info->flowspec->token_bucket_size);
                }
                break;

            case RSVP_CLASS_ERROR_SPEC:
                if (info->error_spec) break;
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
                if (info->sender_v4) break;
                if ((obj_hdr->c_type == 1 || obj_hdr->c_type == 7) &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_sender_ipv4)) {
                    info->sender_v4 = (struct rsvp_sender_ipv4*)obj_data;
                    memcpy(&info->key.sender, info->sender_v4, sizeof(struct rsvp_sender_ipv4));
                    char src_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &info->sender_v4->source_addr, src_str, sizeof(src_str));
                    LOG_DEBUG("  - SENDER/FILTER IPv4: Source %s, LSP-ID %d", src_str, ntohs(info->sender_v4->lsp_id));
                }
                break;

            case RSVP_CLASS_SENDER_TSPEC:
                if (info->tspec) break;
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_sender_tspec)) {
                    info->tspec = (struct rsvp_sender_tspec*)obj_data;
                    LOG_DEBUG("  - SENDER TSPEC: Rate %.2f, Size %.2f",
                              info->tspec->token_bucket_rate, info->tspec->token_bucket_size);
                }
                break;

            case RSVP_CLASS_ADSPEC:
                if (info->adspec) break;
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_adspec)) {
                    info->adspec = (struct rsvp_adspec*)obj_data;
                    LOG_DEBUG("  - ADSPEC: Version %d, Length %d words",
                              info->adspec->version, ntohs(info->adspec->length));
                }
                break;

            case RSVP_CLASS_LABEL:
                if (info->label) break;
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_label_ipv4)) {
                    info->label = (struct rsvp_label_ipv4*)obj_data;
                    LOG_DEBUG("  - LABEL: %u", ntohl(info->label->label) >> 12);
                }
                break;

            case RSVP_CLASS_LABEL_REQUEST:
                if (info->label_req) break;
                if (obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_label_request)) {
                    info->label_req = (struct rsvp_label_request*)obj_data;
                    LOG_DEBUG("  - LABEL REQUEST: L3PID 0x%04x", ntohs(info->label_req->l3pid));
                }
                break;

            case RSVP_CLASS_EXPLICIT_ROUTE:
                if (info->ero) break;
                if (obj_len > sizeof(struct rsvp_obj_hdr)) {
                    info->ero = (struct rsvp_ero_ipv4_subobj*)obj_data;
                    info->ero_len = obj_len - sizeof(struct rsvp_obj_hdr);
                    LOG_DEBUG("  - ERO: Length %zu", info->ero_len);
                }
                break;

            case RSVP_CLASS_RECORD_ROUTE:
                if (info->rro) break;
                if (obj_len > sizeof(struct rsvp_obj_hdr)) {
                    info->rro = (struct rsvp_ero_ipv4_subobj*)obj_data;
                    info->rro_len = obj_len - sizeof(struct rsvp_obj_hdr);
                    LOG_DEBUG("  - RRO: Length %zu", info->rro_len);
                }
                break;

            case RSVP_CLASS_SESSION_ATTRIB:
                if (info->sess_attr) break;
                if (obj_hdr->c_type == 7 &&
                    obj_len >= sizeof(struct rsvp_obj_hdr) + sizeof(struct rsvp_session_attribute)) {
                    info->sess_attr = (struct rsvp_session_attribute*)obj_data;
                    size_t data_len = obj_len - sizeof(struct rsvp_obj_hdr);
                    if (info->sess_attr->name_length > 0) {
                        size_t nlen = info->sess_attr->name_length;
                        /* Safety check: ensure name doesn't exceed object length */
                        if (sizeof(struct rsvp_session_attribute) + nlen > data_len) {
                            LOG_WARN("Parser: SESSION_ATTRIB name length %zu exceeds object data length %zu", nlen, data_len - sizeof(struct rsvp_session_attribute));
                            nlen = data_len - sizeof(struct rsvp_session_attribute);
                        }
                        if (nlen >= sizeof(info->lsp_name)) nlen = sizeof(info->lsp_name) - 1;
                        memcpy(info->lsp_name, info->sess_attr->name, nlen);
                        info->lsp_name[nlen] = '\0';
                        LOG_DEBUG("  - SESSION ATTRIB: Name %s", info->lsp_name);
                    }
                }
                break;

            default:
                /* Handle unrecognized objects according to RFC 2205 class number rules */
                if (obj_hdr->class_num < 128) {
                    LOG_WARN("Parser: Unhandled object class %d (Class-Num < 128). Rejecting message.", obj_hdr->class_num);
                    return RSVP_PROTO_ERR_UNKNOWN_OBJECT_CLASS;
                } else if (obj_hdr->class_num < 192) {
                    LOG_DEBUG("  - Unhandled object class %d (Ignore and forward)", obj_hdr->class_num);
                } else {
                    LOG_DEBUG("  - Unhandled object class %d (Ignore and drop)", obj_hdr->class_num);
                }
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
            if (!info->style) {
                LOG_WARN("Parser: RESV missing mandatory STYLE object");
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
            if (!info->hop_v4 && !info->hop_v6) {
                LOG_WARN("Parser: RESVTEAR missing mandatory RSVP_HOP object");
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
