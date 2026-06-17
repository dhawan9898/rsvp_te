/**
 * @file rsvp_state_machine.c
 * @brief RSVP State Machine Implementation.
 * @details Handles the processing of RSVP messages, state creation/deletion, timer management, and hardware programming.
 */

#include "rsvp_state_machine.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "common/rsvp_log.h"
#include "hal/hal_netlink.h"
#include "label_mgr.h"
#include "pi/rsvp_builder.h"
#include "pi/rsvp_timers.h"
#include "rsvp_dispatcher.h"
#include "rsvp_state_db.h"

#define RSVP_REFRESH_MS 30000
#define RSVP_K_VALUE 3
#define RSVP_CLEANUP_MS(R) ((uint32_t)(RSVP_K_VALUE * (R)))

static uint16_t next_lsp_id = 1;

static uint32_t get_jittered_refresh(uint32_t base_ms, bool is_backup) {
    if (base_ms == 0) base_ms = RSVP_REFRESH_MS;

    if (is_backup) {
        /* Backup timer (Transit): Should be slightly longer than R
         * to avoid unnecessary refreshes when upstream is healthy.
         * Wait between 1.1R and 1.3R.
         */
        uint32_t min = (uint32_t)(base_ms * 1.1);
        uint32_t max = (uint32_t)(base_ms * 1.3);
        uint32_t range = max - min;
        if (range == 0) range = 1;
        return min + (rand() % range);
    } else {
        /* Trigger timer (Ingress/Egress): 0.8R to 1.2R */
        uint32_t min = (uint32_t)(base_ms * 0.8);
        uint32_t max = (uint32_t)(base_ms * 1.2);
        uint32_t range = max - min;
        if (range == 0) range = 1;
        return min + (rand() % range);
    }
}

/* Forward declarations */
static void psb_refresh_timer_cb(void* arg);
static void psb_cleanup_timer_cb(void* arg);
static void rsb_refresh_timer_cb(void* arg);
static void rsb_cleanup_timer_cb(void* arg);
static void send_resv_upstream(struct rsvp_rsb* rsb);
static void propagate_path_tear(struct rsvp_psb* psb);
static void propagate_resv_tear(struct rsvp_rsb* rsb);
static void propagate_resv_err(struct rsvp_rsb* rsb, struct rsvp_error_spec_ipv4* err_spec);
static void send_path_downstream(struct rsvp_psb* psb);
static void rsvp_psb_cleanup(struct rsvp_psb* psb, bool propagate);
static void rsvp_rsb_cleanup(struct rsvp_rsb* rsb, bool propagate);

static void send_path_err(struct rsvp_message_info* info, uint8_t error_code, uint16_t error_value) {
    uint8_t buf[1024];
    struct rsvp_builder b;
    struct in_addr dest = info->key.session.dest_addr;
    struct in_addr src = info->src_ip;

    char dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest, dest_str, sizeof(dest_str));
    LOG_INFO("  - Sending PathErr to %s [Code: %d, Val: %d]", inet_ntoa(src), error_code, error_value);

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATHERR);
    b.hdr->ttl = 255;

    struct in_addr ext_dest = info->key.session.extended_tunnel_id;
    rsvp_builder_add_session_ipv4(&b, &dest, ntohs(info->key.session.tunnel_id), &ext_dest);

    /* ERROR_SPEC */
    struct rsvp_error_spec_ipv4 err_spec;
    memset(&err_spec, 0, sizeof(err_spec));
    struct in_addr local_node;
    hal_netlink_get_local_addr(0, &local_node);
    err_spec.error_node = local_node;
    err_spec.flags = 0;
    err_spec.error_code = error_code;
    err_spec.error_value = htons(error_value);
    rsvp_builder_add_obj(&b, RSVP_CLASS_ERROR_SPEC, 1, &err_spec, sizeof(err_spec));

    /* SENDER_TEMPLATE */
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &info->key.sender, sizeof(info->key.sender));

    size_t len = rsvp_builder_finalize(&b);
    struct in_addr local_addr = {0};
    rsvp_send_packet(&local_addr, &src, buf, len, false);
}

static rsvp_error_t rsvp_validate_path_message(struct rsvp_message_info* info, struct rsvp_psb* existing_psb, uint8_t* err_code, uint16_t* err_val) {
    if (!info->hop_v4) {
        LOG_WARN("  - Validation: PATH missing RSVP_HOP object");
        *err_code = RSVP_ERR_UNKNOWN_OBJECT_CLASS;
        *err_val = (RSVP_CLASS_HOP << 8);
        return RSVP_ERR_MALFORMED_OBJ;
    }

    if (!info->sender_v4) {
        LOG_WARN("  - Validation: PATH missing SENDER_TEMPLATE object");
        *err_code = RSVP_ERR_UNKNOWN_OBJECT_CLASS;
        *err_val = (RSVP_CLASS_SENDER_TEMPLATE << 8);
        return RSVP_ERR_MALFORMED_OBJ;
    }

    /* For RSVP-TE, LABEL_REQUEST is mandatory for new paths */
    if (!info->label_req && !existing_psb) {
        LOG_WARN("  - Validation: New PATH missing LABEL_REQUEST object");
        *err_code = RSVP_ERR_UNKNOWN_OBJECT_CLASS;
        *err_val = (RSVP_CLASS_LABEL_REQUEST << 8);
        return RSVP_ERR_MALFORMED_OBJ;
    }

    if (existing_psb) {
        /* RFC 2205: Check for incompatible state changes if any.
         * Our rsvp_psb_find uses SESSION and SENDER_TEMPLATE as key.
         * If they changed, it's considered a new path.
         */
        LOG_DEBUG("  - Validation: Existing PSB found, checking for updates");
    }

    return RSVP_SUCCESS;
}

static rsvp_error_t rsvp_validate_resv_message(struct rsvp_message_info* info, struct rsvp_rsb* existing_rsb, uint8_t* err_code, uint16_t* err_val) {
    (void)existing_rsb;
    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    if (!psb) {
        LOG_WARN("  - Validation: No matching PSB for RESV");
        /* RFC 2205: If no path state, send ResvErr with Code 3 */
        *err_code = RSVP_ERR_NO_PATH_STATE;
        *err_val = 0; 
        return RSVP_ERR_NOT_FOUND;
    }

    if (!info->hop_v4) {
        LOG_WARN("  - Validation: RESV missing RSVP_HOP object");
        *err_code = RSVP_ERR_UNKNOWN_OBJECT_CLASS;
        *err_val = (RSVP_CLASS_HOP << 8);
        return RSVP_ERR_MALFORMED_OBJ;
    }

    if (!info->label) {
        LOG_WARN("  - Validation: RESV missing LABEL object");
        *err_code = RSVP_ERR_UNKNOWN_OBJECT_CLASS;
        *err_val = (RSVP_CLASS_LABEL << 8);
        return RSVP_ERR_MALFORMED_OBJ;
    }

    return RSVP_SUCCESS;
}

static void handle_path_message(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN], hop_str[INET_ADDRSTRLEN] = "N/A";
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->key.sender.source_addr, src_str, sizeof(src_str));
    if (info->hop_v4) {
        inet_ntop(AF_INET, &info->hop_v4->neighbor_addr, hop_str, sizeof(hop_str));
    }

    LOG_INFO("Handling PATH: [TunnelID: %d, Dest: %s, Source: %s, PrevHop: %s]",
             ntohs(info->key.session.tunnel_id), dest_str, src_str, hop_str);

    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    uint8_t err_code = 0;
    uint16_t err_val = 0;

    if (rsvp_validate_path_message(info, psb, &err_code, &err_val) != RSVP_SUCCESS) {
        LOG_WARN("  - PATH validation failed. Sending PathErr.");
        send_path_err(info, err_code, err_val);
        return;
    }

    struct in_addr dest;
    bool is_new = (psb == NULL);

    if (is_new) {
        LOG_INFO("  - New PATH detected, creating PSB");
        psb = rsvp_psb_create(&info->key);
        if (!psb) return;
        psb->refresh_ms = RSVP_REFRESH_MS;
    } else {
        LOG_DEBUG("  - Found existing PSB");
        /* Check if PHOP changed (could happen during re-routing) */
        if (info->hop_v4 && memcmp(&psb->prev_hop.neighbor_addr, &info->hop_v4->neighbor_addr, sizeof(struct in_addr)) != 0) {
            char old_hop[INET_ADDRSTRLEN], new_hop[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &psb->prev_hop.neighbor_addr, old_hop, sizeof(old_hop));
            inet_ntop(AF_INET, &info->hop_v4->neighbor_addr, new_hop, sizeof(new_hop));
            LOG_INFO("  - PHOP changed from %s to %s. Updating state.", old_hop, new_hop);
        }
    }

    if (!info->hop_v4) {
        LOG_WARN("  - PATH missing RSVP_HOP object. Dropping.");
        if (is_new) rsvp_psb_delete(psb);
        return;
    }

    if (info->time_values) {
        psb->refresh_ms = ntohl(info->time_values->refresh_ms);
        LOG_DEBUG("  - Updated Refresh Interval: %u ms", psb->refresh_ms);
    }

    if (info->common_hdr) {
        psb->ttl = info->common_hdr->ttl;
        LOG_DEBUG("  - Message TTL: %u", psb->ttl);
    }

    /* Reset Refresh Counter */
    psb->refresh_count = 0;

    if (info->lsp_name[0] != '\0') {
        if (psb->lsp_name) free(psb->lsp_name);
        psb->lsp_name = strdup(info->lsp_name);
        LOG_DEBUG("  - LSP Name: %s", psb->lsp_name);
    }

    /* Reset Cleanup Timer */
    if (!psb->is_ingress) {
        uint32_t cleanup_ms = RSVP_CLEANUP_MS(psb->refresh_ms);
        LOG_DEBUG("  - (Re)starting Cleanup Timer: %u ms", cleanup_ms);
        if (!psb->cleanup_timer.active ||
            !rsvp_timer_reset(&psb->cleanup_timer, cleanup_ms)) {
            rsvp_timer_start(&psb->cleanup_timer,
                RSVP_TIMER_CLEANUP, cleanup_ms, psb_cleanup_timer_cb, psb);
        }
    }

    /* Refresh Timer: Ensure it is running */
    if (!psb->refresh_timer.active) {
        uint32_t next_refresh = get_jittered_refresh(psb->refresh_ms, !psb->is_ingress);
        LOG_DEBUG("  - Starting Refresh Timer: %u ms (Jittered)", next_refresh);
        rsvp_timer_start(&psb->refresh_timer,
            RSVP_TIMER_REFRESH, next_refresh, psb_refresh_timer_cb, psb);
    }

    if (info->hop_v4) {
        psb->prev_hop = *info->hop_v4;
        psb->ifindex_in = ntohl(info->hop_v4->logical_interface);
        LOG_DEBUG("  - Input Interface Index: %u", psb->ifindex_in);
    }

    dest = info->key.session.dest_addr;
    if (hal_netlink_is_local_addr(&dest)) {
        /* Egress: We are the tail-end. Triggering RESV... */
        LOG_INFO("  - Role: EGRESS (Dest %s is local)", dest_str);
        struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
        if (!rsb) {
            LOG_INFO("  - Triggering initial RESV...");
            rsb = rsvp_rsb_create(&info->key);
            if (rsb) {
                rsb->associated_psb = psb;
                psb->associated_rsb = rsb;
                rsb->refresh_ms = psb->refresh_ms;

                uint32_t resv_refresh = get_jittered_refresh(rsb->refresh_ms, false);
                LOG_DEBUG("  - Starting RSB Refresh Timer: %u ms", resv_refresh);
                rsvp_timer_start(&rsb->refresh_timer,
                    RSVP_TIMER_REFRESH, resv_refresh, rsb_refresh_timer_cb,
                    rsb);

                send_resv_upstream(rsb);
            }
        } else {
            LOG_DEBUG("  - Existing RSB found at Egress, state refreshed");
            rsb->refresh_ms = psb->refresh_ms;
        }
    } else {
        /* Transit node or Ingress receiving its own packet */
        struct in_addr src_addr = info->key.sender.source_addr;
        if (hal_netlink_is_local_addr(&src_addr)) {
            LOG_WARN("  - Role: INGRESS (Own PATH back). Dropping to prevent loop.");
            return;
        }

        struct in_addr next_hop = {0};
        int out_ifindex = hal_netlink_get_egress_if(&dest, &next_hop);

        if (out_ifindex < 0) {
            LOG_ERROR("  - Role: TRANSIT. No route to dest %s. Sending PathErr.", dest_str);
            /* Error Code 2: Routing problem, Error Value 0: No route to destination */
            send_path_err(info, 2, 0);
            if (is_new) rsvp_psb_delete(psb);
            return;
        }

        char nh_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &next_hop, nh_str, sizeof(nh_str));
        LOG_INFO("  - Role: TRANSIT. NextHop: %s, OutIf: %d", nh_str, out_ifindex);

        psb->ifindex_out = out_ifindex;

        LOG_INFO("  - Role: TRANSIT, forwarding PATH downstream...");
        send_path_downstream(psb);
    }
}

static void send_resv_err(struct rsvp_message_info* info, uint8_t error_code, uint16_t error_value) {
    uint8_t buf[1024];
    struct rsvp_builder b;
    struct in_addr dest = info->key.session.dest_addr;
    struct in_addr src = info->src_ip;

    LOG_INFO("  - Sending ResvErr to %s [Code: %d, Val: %d]", inet_ntoa(src), error_code, error_value);

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESVERR);
    b.hdr->ttl = 255;

    struct in_addr ext_dest = info->key.session.extended_tunnel_id;
    rsvp_builder_add_session_ipv4(&b, &dest, ntohs(info->key.session.tunnel_id), &ext_dest);

    struct rsvp_error_spec_ipv4 err_spec;
    memset(&err_spec, 0, sizeof(err_spec));
    struct in_addr local_node;
    hal_netlink_get_local_addr(0, &local_node);
    err_spec.error_node = local_node;
    err_spec.error_code = error_code;
    err_spec.error_value = htons(error_value);
    rsvp_builder_add_obj(&b, RSVP_CLASS_ERROR_SPEC, 1, &err_spec, sizeof(err_spec));

    rsvp_builder_add_style(&b, RSVP_STYLE_FF);
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7, &info->key.sender, sizeof(info->key.sender));

    size_t len = rsvp_builder_finalize(&b);
    struct in_addr local_addr = {0};
    rsvp_send_packet(&local_addr, &src, buf, len, false);
}

static void handle_resv_message(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN], nh_str[INET_ADDRSTRLEN] = "N/A";
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->key.sender.source_addr, src_str, sizeof(src_str));
    if (info->hop_v4) {
        inet_ntop(AF_INET, &info->hop_v4->neighbor_addr, nh_str, sizeof(nh_str));
    }

    struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
    uint8_t err_code = 0;
    uint16_t err_val = 0;

    if (rsvp_validate_resv_message(info, rsb, &err_code, &err_val) != RSVP_SUCCESS) {
        LOG_WARN("  - RESV validation failed. Sending ResvErr.");
        send_resv_err(info, err_code, err_val);
        return;
    }

    uint32_t label = ntohl(info->label->label) >> 12;

    LOG_INFO("Handling RESV: [TunnelID: %d, Dest: %s, Source: %s, Label: %u, NextHop: %s]",
             ntohs(info->key.session.tunnel_id), dest_str, src_str, label, nh_str);

    bool is_new = (rsb == NULL);

    if (is_new) {
        LOG_INFO("  - New RESV detected, creating RSB");
        rsb = rsvp_rsb_create(&info->key);
        if (!rsb) return;
        rsb->refresh_ms = RSVP_REFRESH_MS;

        struct rsvp_psb* psb = rsvp_psb_find(&info->key);
        if (psb) {
            LOG_DEBUG("  - Associated RSB with existing PSB");
            rsb->associated_psb = psb;
            psb->associated_rsb = rsb;
            rsb->refresh_ms = psb->refresh_ms;
        }
    } else {
        LOG_DEBUG("  - Found existing RSB");
    }

    if (info->time_values) {
        rsb->refresh_ms = ntohl(info->time_values->refresh_ms);
        LOG_DEBUG("  - Updated RSB Refresh Interval: %u ms", rsb->refresh_ms);
    }

    if (info->common_hdr) {
        rsb->ttl = info->common_hdr->ttl;
        LOG_DEBUG("  - RSB Message TTL: %u", rsb->ttl);
    }

    /* Reset Cleanup Timer */
    uint32_t cleanup_ms = RSVP_CLEANUP_MS(rsb->refresh_ms);
    LOG_DEBUG("  - (Re)starting RSB Cleanup Timer: %u ms", cleanup_ms);
    if (!rsb->cleanup_timer.active ||
        !rsvp_timer_reset(&rsb->cleanup_timer, cleanup_ms)) {
        rsvp_timer_start(&rsb->cleanup_timer,
            RSVP_TIMER_CLEANUP, cleanup_ms, rsb_cleanup_timer_cb, rsb);
    }

    rsb->refresh_count = 0;
    /* Refresh Timer: Only for Transit and Egress nodes (upstream refresh) */
    if (rsb->associated_psb && !rsb->associated_psb->is_ingress) {
        if (!rsb->refresh_timer.active) {
            uint32_t next_refresh_rsb = get_jittered_refresh(rsb->refresh_ms, true);
            LOG_DEBUG("  - Starting RSB Upstream Refresh Timer: %u ms", next_refresh_rsb);
            rsvp_timer_start(&rsb->refresh_timer,
                RSVP_TIMER_REFRESH, next_refresh_rsb, rsb_refresh_timer_cb, rsb);
        }
    } else if (rsb->refresh_timer.active) {
        LOG_DEBUG("  - Stopping RSB Refresh Timer (Role is now Ingress or No PSB)");
        rsvp_timer_stop(&rsb->refresh_timer);
    }

    uint32_t old_label_out = rsb->label_out;
    struct in_addr old_next_hop = rsb->next_hop.neighbor_addr;

    if (info->label) {
        rsb->label_out = label;
    }

    if (info->hop_v4) {
        rsb->next_hop = *info->hop_v4;
    }

    bool label_changed = (rsb->label_out != old_label_out);
    bool hop_changed = (memcmp(&rsb->next_hop.neighbor_addr, &old_next_hop, sizeof(struct in_addr)) != 0);

    if (is_new || label_changed || hop_changed) {
        if (rsb->associated_psb) {
            struct rsvp_psb* psb = rsb->associated_psb;
            struct in_addr next_hop_addr = rsb->next_hop.neighbor_addr;
            
            if (label_changed) {
                LOG_INFO("  - Label changed from %u to %u", old_label_out, rsb->label_out);
            }
            if (hop_changed) {
                char old_nh[INET_ADDRSTRLEN], new_nh[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &old_next_hop, old_nh, sizeof(old_nh));
                inet_ntop(AF_INET, &next_hop_addr, new_nh, sizeof(new_nh));
                LOG_INFO("  - NextHop changed from %s to %s", old_nh, new_nh);
            }

            if (psb->prev_hop.neighbor_addr.s_addr != 0) {
                /* Transit node */
                if (rsb->label_in == 0) {
                    rsb->label_in = label_mgr_alloc();
                    LOG_DEBUG("  - Allocated Inbound Label: %u", rsb->label_in);
                }
                LOG_INFO("  - TRANSIT: Programming MPLS SWAP [%u -> %u] via if %u",
                         rsb->label_in, rsb->label_out,
                         ntohl(rsb->next_hop.logical_interface));
                hal_mpls_install(rsb->label_in, rsb->label_out,
                                 ntohl(rsb->next_hop.logical_interface),
                                 &next_hop_addr);
                
                char prev_hop_buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &psb->prev_hop.neighbor_addr, prev_hop_buf, sizeof(prev_hop_buf));
                LOG_INFO("  - Forwarding RESV upstream to %s", prev_hop_buf);
                send_resv_upstream(rsb);
            } else {
                /* Ingress node */
                LOG_INFO("  - INGRESS: Programming MPLS PUSH [-> %u] via if %u",
                         rsb->label_out,
                         ntohl(rsb->next_hop.logical_interface));
                hal_mpls_install(0, rsb->label_out,
                                 ntohl(rsb->next_hop.logical_interface),
                                 &next_hop_addr);
                LOG_INFO("  - INGRESS: Reservation COMPLETE for Tunnel %d",
                         ntohs(rsb->key.session.tunnel_id));
            }
        } else {
            LOG_WARN("  - RSB has no associated PSB, cannot program hardware!");
        }
    } else {
        LOG_DEBUG("  - RSB state refreshed (no label change), forwarding upstream...");
        if (rsb->associated_psb && rsb->associated_psb->prev_hop.neighbor_addr.s_addr != 0) {
            char prev_hop_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &rsb->associated_psb->prev_hop.neighbor_addr, prev_hop_buf, sizeof(prev_hop_buf));
            LOG_INFO("  - Forwarding RESV refresh upstream to %s", prev_hop_buf);
            send_resv_upstream(rsb);
        }
    }
}

static void handle_path_tear(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN], sender_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->key.sender.source_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &info->src_ip, sender_str, sizeof(sender_str));

    LOG_INFO("Handling PathTear from %s: [TunnelID: %d, Dest: %s, Source: %s]",
             sender_str, ntohs(info->key.session.tunnel_id), dest_str, src_str);

    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    if (psb) {
        rsvp_psb_cleanup(psb, true);
    } else {
        LOG_WARN("  - No matching PSB found for PathTear (from %s), ignoring.", sender_str);
    }
}

static void handle_resv_tear(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN], sender_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->key.sender.source_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &info->src_ip, sender_str, sizeof(sender_str));

    LOG_INFO("Handling ResvTear from %s: [TunnelID: %d, Dest: %s, Source: %s]",
             sender_str, ntohs(info->key.session.tunnel_id), dest_str, src_str);

    struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
    if (rsb) {
        rsvp_rsb_cleanup(rsb, true);
    } else {
        LOG_WARN("  - No matching RSB found for ResvTear (from %s), ignoring.", sender_str);
    }
}

static void handle_path_err(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN], node_str[INET_ADDRSTRLEN] = "N/A", sender_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->key.sender.source_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &info->src_ip, sender_str, sizeof(sender_str));

    if (info->error_spec) {
        inet_ntop(AF_INET, &info->error_spec->error_node, node_str, sizeof(node_str));
        LOG_INFO("Handling PathErr from %s: [TunnelID: %d, Dest: %s, Source: %s] Code: %d, Val: %d, Node: %s",
                 sender_str, ntohs(info->key.session.tunnel_id), dest_str, src_str,
                 info->error_spec->error_code, info->error_spec->error_value, node_str);
    } else {
        LOG_WARN("Handling PathErr from %s: [TunnelID: %d, Dest: %s, Source: %s] MISSING ERROR_SPEC",
                 sender_str, ntohs(info->key.session.tunnel_id), dest_str, src_str);
    }

    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    if (psb && psb->prev_hop.neighbor_addr.s_addr != 0) {
        char prev_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &psb->prev_hop.neighbor_addr, prev_str, sizeof(prev_str));
        LOG_INFO("  - Propagating PathErr upstream to %s...", prev_str);
        
        struct in_addr prev_addr = psb->prev_hop.neighbor_addr;
        struct in_addr local_addr = {0};
        struct in_addr dummy;
        int out_ifindex = hal_netlink_get_egress_if(&prev_addr, &dummy);
        if (out_ifindex >= 0) {
            hal_netlink_get_local_addr(out_ifindex, &local_addr);
        } else {
            local_addr = psb->key.session.dest_addr; /* Fallback */
        }

        /* Rebuild message to ensure correct HOP object and checksum */
        uint8_t buf[1024];
        struct rsvp_builder b;
        rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATHERR);
        
        /* Set TTL */
        b.hdr->ttl = (info->common_hdr->ttl > 0) ? info->common_hdr->ttl - 1 : 255;

        struct in_addr dest_addr_cpy = psb->key.session.dest_addr;
        struct in_addr ext_dest_cpy = psb->key.session.extended_tunnel_id;
        rsvp_builder_add_session_ipv4(&b, &dest_addr_cpy, 
                                      ntohs(psb->key.session.tunnel_id),
                                      &ext_dest_cpy);
        
        rsvp_builder_add_hop_ipv4(&b, &local_addr, 
                                  out_ifindex >= 0 ? (uint32_t)out_ifindex : psb->ifindex_in);
        
        if (info->error_spec) {
            rsvp_builder_add_obj(&b, RSVP_CLASS_ERROR_SPEC, 1, info->error_spec, sizeof(*info->error_spec));
        }

        /* SENDER_TEMPLATE */
        rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &psb->key.sender, sizeof(psb->key.sender));

        size_t len = rsvp_builder_finalize(&b);
        if (rsvp_send_packet(&local_addr, &prev_addr, buf, len, false) < 0) {
            LOG_ERROR("  - Failed to send PathErr upstream to %s", prev_str);
        }
    } else {
        LOG_INFO("  - PathErr reached Ingress (Head-end) or no PSB found. Error processing complete.");
    }
}

static void handle_resv_err(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN], node_str[INET_ADDRSTRLEN] = "N/A", sender_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->key.sender.source_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &info->src_ip, sender_str, sizeof(sender_str));

    if (info->error_spec) {
        inet_ntop(AF_INET, &info->error_spec->error_node, node_str, sizeof(node_str));
        LOG_INFO("Handling ResvErr from %s: [TunnelID: %d, Dest: %s, Source: %s] Code: %d, Val: %d, Node: %s",
                 sender_str, ntohs(info->key.session.tunnel_id), dest_str, src_str,
                 info->error_spec->error_code, info->error_spec->error_value, node_str);
    } else {
        LOG_WARN("Handling ResvErr from %s: [TunnelID: %d, Dest: %s, Source: %s] MISSING ERROR_SPEC",
                 sender_str, ntohs(info->key.session.tunnel_id), dest_str, src_str);
    }

    struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
    if (rsb) {
        /* Check if we are Egress */
        struct in_addr dest_addr_cpy = info->key.session.dest_addr;
        if (hal_netlink_is_local_addr(&dest_addr_cpy)) {
            LOG_INFO("  - ResvErr reached Egress (Tail-end). Error processing complete.");
            return;
        }

        LOG_INFO("  - Propagating ResvErr downstream...");
        propagate_resv_err(rsb, info->error_spec);
    } else {
        LOG_WARN("  - No matching RSB found for ResvErr (from %s), ignoring.", sender_str);
    }
}

/**
 * @brief Main entry point for processing an incoming RSVP message.
 * @details Dispatches the parsed message to the appropriate handler based on its type.
 * @param [in] info Pointer to the parsed RSVP message information.
 */
void rsvp_handle_message(struct rsvp_message_info* info) {
    switch (info->common_hdr->msg_type) {
        case RSVP_MSG_PATH:
            handle_path_message(info);
            break;
        case RSVP_MSG_RESV:
            handle_resv_message(info);
            break;
        case RSVP_MSG_PATHTEAR:
            handle_path_tear(info);
            break;
        case RSVP_MSG_RESVTEAR:
            handle_resv_tear(info);
            break;
        case RSVP_MSG_PATHERR:
            handle_path_err(info);
            break;
        case RSVP_MSG_RESVERR:
            handle_resv_err(info);
            break;
        default:
            LOG_INFO("Unsupported message type: %d",
                     info->common_hdr->msg_type);
            break;
    }
}

static void send_resv_upstream(struct rsvp_rsb* rsb) {
    uint8_t buf[1024];
    struct rsvp_builder b;
    struct rsvp_psb* psb = rsb->associated_psb;
    if (!psb) {
        LOG_ERROR("send_resv_upstream: No associated PSB found!");
        return;
    }

    if (rsb->label_in == 0) {
        rsb->label_in = label_mgr_alloc();
        if (rsb->label_in == 0) {
            LOG_ERROR("send_resv_upstream: Failed to allocate label_in");
            return;
        }
        LOG_DEBUG("  - Allocated label_in: %u", rsb->label_in);
    }

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESV);
    b.hdr->ttl = (rsb->ttl > 0) ? rsb->ttl - 1 : 255;

    struct in_addr dest = psb->key.session.dest_addr;
    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;
    struct in_addr nbr = psb->prev_hop.neighbor_addr;

    rsvp_builder_add_session_ipv4(&b, &dest, ntohs(psb->key.session.tunnel_id),
                                  &ext_dest);

    /* Calculate local IP for RESV HOP object */
    struct in_addr local_addr = {0};
    struct in_addr dummy_next_hop;
    int out_ifindex = hal_netlink_get_egress_if(&nbr, &dummy_next_hop);
    if (out_ifindex >= 0) {
        hal_netlink_get_local_addr(out_ifindex, &local_addr);
    }
    rsvp_builder_add_hop_ipv4(
        &b, &local_addr,
        out_ifindex >= 0 ? (uint32_t)out_ifindex : psb->ifindex_in);

    rsvp_builder_add_time_values(&b, rsb->refresh_ms);

    /* STYLE object */
    rsvp_builder_add_style(&b, RSVP_STYLE_FF);

    struct rsvp_sender_tspec flow_spec;
    memset(&flow_spec, 0, sizeof(flow_spec));
    flow_spec.version = 0;
    flow_spec.length = (sizeof(flow_spec) / 4) - 1;
    flow_spec.service_hdr = 5;
    flow_spec.svc_length = 6;
    flow_spec.param_id = 127;
    flow_spec.param_length = 5;
    flow_spec.token_bucket_rate = 1000000.0f;
    flow_spec.token_bucket_size = 1000.0f;
    flow_spec.peak_data_rate = 1000000.0f;
    flow_spec.min_policed_unit = 64;
    flow_spec.max_packet_size = 1500;
    rsvp_builder_add_flowspec(&b, &flow_spec);

    /* FILTER_SPEC uses C-Type 7 for IPv4 LSP */
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7, &psb->key.sender,
                         sizeof(psb->key.sender));
    rsvp_builder_add_label_ipv4(&b, rsb->label_in);

    size_t len = rsvp_builder_finalize(&b);
    struct in_addr nbr_addr = psb->prev_hop.neighbor_addr;
    
    char nbr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &nbr_addr, nbr_str, sizeof(nbr_str));
    LOG_INFO("  - Sending RESV upstream to %s (Length: %zu)", nbr_str, len);
    
    rsvp_send_packet(&local_addr, &nbr_addr, buf, len, false);
}

static void propagate_path_tear(struct rsvp_psb* psb) {
    struct rsvp_session_ipv4 session = psb->key.session;
    struct in_addr dest_addr = session.dest_addr;
    struct in_addr ext_dest = session.extended_tunnel_id;
    struct in_addr next_hop = {0};
    int out_ifindex = hal_netlink_get_egress_if(&dest_addr, &next_hop);
    
    char dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_addr, dest_str, sizeof(dest_str));

    if (out_ifindex < 0) {
        LOG_WARN("Propagate PathTear: no route to dest %s, cannot propagate", dest_str);
        return;
    }

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATHTEAR);
    
    /* Set TTL */
    b.hdr->ttl = (psb->ttl > 0) ? psb->ttl - 1 : 255;

    rsvp_builder_add_session_ipv4(&b, &dest_addr, ntohs(session.tunnel_id),
                                  &ext_dest);

    struct in_addr local_addr = {0};
    if (hal_netlink_get_local_addr(out_ifindex, &local_addr) < 0) {
        local_addr = psb->key.sender.source_addr;
    }
    rsvp_builder_add_hop_ipv4(&b, &local_addr, out_ifindex);

    /* SENDER_TEMPLATE - Mandatory per RFC 2205 */
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &psb->key.sender,
                         sizeof(psb->key.sender));
    
    size_t len = rsvp_builder_finalize(&b);
    LOG_INFO("  - Sending PathTear downstream to %s (Length: %zu)", dest_str, len);
    if (rsvp_send_packet(&local_addr, &dest_addr, buf, len, true) < 0) {
        LOG_ERROR("  - Failed to send PathTear downstream to %s", dest_str);
    }
}

static void propagate_resv_err(struct rsvp_rsb* rsb, struct rsvp_error_spec_ipv4* err_spec) {
    if (!rsb->associated_psb) {
        LOG_WARN("propagate_resv_err: No associated PSB found!");
        return;
    }

    struct rsvp_psb* psb = rsb->associated_psb;
    struct in_addr dest_addr = psb->key.session.dest_addr;
    struct in_addr next_hop = {0};
    int out_ifindex = hal_netlink_get_egress_if(&dest_addr, &next_hop);

    if (out_ifindex < 0) {
        LOG_WARN("propagate_resv_err: No route to dest for ResvErr");
        return;
    }

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESVERR);
    
    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;
    rsvp_builder_add_session_ipv4(&b, &dest_addr, ntohs(psb->key.session.tunnel_id),
                                  &ext_dest);

    struct in_addr local_addr = {0};
    hal_netlink_get_local_addr(out_ifindex, &local_addr);
    rsvp_builder_add_hop_ipv4(&b, &local_addr, out_ifindex);
    
    if (err_spec) {
        rsvp_builder_add_obj(&b, RSVP_CLASS_ERROR_SPEC, 1, err_spec, sizeof(*err_spec));
    }

    /* STYLE object - required in ResvErr */
    rsvp_builder_add_style(&b, RSVP_STYLE_FF);

    /* FILTER_SPEC */
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7, &psb->key.sender, sizeof(psb->key.sender));

    size_t len = rsvp_builder_finalize(&b);
    LOG_INFO("  - Propagating ResvErr downstream towards %s", inet_ntoa(dest_addr));
    rsvp_send_packet(&local_addr, &dest_addr, buf, len, false);
}

static void rsb_cleanup_resources(struct rsvp_rsb* rsb) {
    if (!rsb) return;

    bool is_ingress = (rsb->associated_psb && rsb->associated_psb->is_ingress);

    if (rsb->label_in != 0) {
        LOG_DEBUG("  - Removing MPLS entry for Label %u", rsb->label_in);
        hal_mpls_install(rsb->label_in, 0, 0, NULL); /* Ensure it's removed in HAL if remove not enough */
        hal_mpls_remove(rsb->label_in);
        label_mgr_free(rsb->label_in);
        rsb->label_in = 0;
    } else if (is_ingress) {
        LOG_DEBUG("  - Removing Ingress MPLS entry");
        hal_mpls_remove(0);
    }

    rsvp_timer_stop(&rsb->refresh_timer);
    rsvp_timer_stop(&rsb->cleanup_timer);
}

static void rsvp_rsb_cleanup(struct rsvp_rsb* rsb, bool propagate) {
    if (!rsb) return;

    if (propagate) {
        bool is_ingress = (rsb->associated_psb && rsb->associated_psb->is_ingress);
        if (!is_ingress) {
            propagate_resv_tear(rsb);
        }
    }

    rsb_cleanup_resources(rsb);

    if (rsb->associated_psb) {
        rsb->associated_psb->associated_rsb = NULL;
    }

    rsvp_rsb_delete(rsb);
}

static void rsvp_psb_cleanup(struct rsvp_psb* psb, bool propagate) {
    if (!psb) return;

    if (propagate) {
        struct in_addr dest_addr = psb->key.session.dest_addr;
        bool is_egress = hal_netlink_is_local_addr(&dest_addr);
        if (!is_egress) {
            propagate_path_tear(psb);
        }
    }

    if (psb->associated_rsb) {
        rsvp_rsb_cleanup(psb->associated_rsb, false); /* RSB cleanup usually doesn't propagate if PSB is gone */
    }

    rsvp_timer_stop(&psb->refresh_timer);
    rsvp_timer_stop(&psb->cleanup_timer);
    rsvp_psb_delete(psb);
}

static void propagate_resv_tear(struct rsvp_rsb* rsb) {
    if (!rsb->associated_psb) {
        LOG_ERROR("propagate_resv_tear: No associated PSB found!");
        return;
    }

    struct rsvp_psb* psb = rsb->associated_psb;
    struct rsvp_session_ipv4 session = psb->key.session;
    struct rsvp_hop_ipv4 prev_hop = psb->prev_hop;
    struct in_addr dest_addr = session.dest_addr;
    struct in_addr ext_dest = session.extended_tunnel_id;
    struct in_addr prev_neighbor = prev_hop.neighbor_addr;

    if (prev_neighbor.s_addr == 0) {
        LOG_DEBUG("propagate_resv_tear: reached Ingress, no upstream neighbor to notify.");
        return;
    }

    char prev_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &prev_neighbor, prev_str, sizeof(prev_str));
    LOG_INFO("  - Propagating ResvTear upstream to %s...", prev_str);

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESVTEAR);
    rsvp_builder_add_session_ipv4(&b, &dest_addr, ntohs(session.tunnel_id),
                                  &ext_dest);
    rsvp_builder_add_hop_ipv4(&b, &prev_neighbor,
                              ntohl(prev_hop.logical_interface));
    rsvp_builder_add_time_values(&b, rsb->refresh_ms);

    /* STYLE object - required for flow descriptor list */
    rsvp_builder_add_style(&b, RSVP_STYLE_FF);

    /* FILTER_SPEC uses C-Type 7 for IPv4 LSP */
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7, &psb->key.sender,
                         sizeof(psb->key.sender));

    size_t len = rsvp_builder_finalize(&b);

    struct in_addr local_addr = {0};
    struct in_addr dummy;
    int ifindex = hal_netlink_get_egress_if(&prev_neighbor, &dummy);
    if (ifindex >= 0) {
        hal_netlink_get_local_addr(ifindex, &local_addr);
    }
    if (rsvp_send_packet(&local_addr, &prev_neighbor, buf, len, false) < 0) {
        LOG_ERROR("  - Failed to send ResvTear upstream to %s", prev_str);
    }
}

static void send_path_downstream(struct rsvp_psb* psb) {
    uint8_t buf[1024];
    struct rsvp_builder b;
    struct in_addr dest_addr = psb->key.session.dest_addr;
    struct in_addr source_addr = psb->key.sender.source_addr;
    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;
    struct in_addr next_hop = {0};

    char dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_addr, dest_str, sizeof(dest_str));

    int ifindex = hal_netlink_get_egress_if(&dest_addr, &next_hop);
    if (ifindex < 0) {
        LOG_ERROR("send_path_downstream: no route to %s", dest_str);
        return;
    }
    psb->ifindex_out = ifindex;

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
    b.hdr->ttl = (psb->ttl > 0) ? psb->ttl - 1 : 255;
    rsvp_builder_add_session_ipv4(&b, &dest_addr,
                                  ntohs(psb->key.session.tunnel_id), &ext_dest);

    struct in_addr local_addr = {0};
    if (hal_netlink_get_local_addr(ifindex, &local_addr) < 0) {
        local_addr = psb->key.sender.source_addr;
    }
    rsvp_builder_add_hop_ipv4(&b, &local_addr, ifindex);
    rsvp_builder_add_time_values(&b, psb->refresh_ms);
    rsvp_builder_add_label_request(&b, 0x0800);
    rsvp_builder_add_session_attribute(&b, psb->lsp_name);

    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &psb->key.sender,
                         sizeof(psb->key.sender));

    struct rsvp_sender_tspec tspec;
    memset(&tspec, 0, sizeof(tspec));
    tspec.version = 0;
    tspec.length = (sizeof(tspec) / 4) - 1;
    tspec.service_hdr = 5;
    tspec.svc_length = 6;
    tspec.param_id = 127;
    tspec.param_length = 5;
    tspec.token_bucket_rate = 1000000.0f;
    tspec.token_bucket_size = 1000.0f;
    tspec.peak_data_rate = 1000000.0f;
    tspec.min_policed_unit = 64;
    tspec.max_packet_size = 1500;
    rsvp_builder_add_tspec(&b, &tspec);

    size_t len = rsvp_builder_finalize(&b);
    LOG_INFO("  - Sending PATH downstream to %s (Length: %zu)", dest_str, len);
    rsvp_send_packet(&source_addr, &dest_addr, buf, len, true);
}

/**
 * @brief Initiate a new RSVP PATH message to establish an LSP.
 * @details Creates a new Path State Block (PSB) at the ingress node and triggers a PATH message downstream.
 * @param [in] src Source (ingress) IPv4 address.
 * @param [in] dest Destination (egress) IPv4 address.
 * @param [in] tunnel_id Tunnel ID for the new LSP.
 * @param [in] lsp_name Optional name for the LSP.
 */
void rsvp_initiate_path(struct in_addr* src, struct in_addr* dest,
                        uint16_t tunnel_id, const char* lsp_name) {
    char src_str[INET_ADDRSTRLEN], dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, src, src_str, sizeof(src_str));
    inet_ntop(AF_INET, dest, dest_str, sizeof(dest_str));

    LOG_INFO("Initiating PATH: [TunnelID: %u, Dest: %s, Source: %s, LSP Name: %s]",
             tunnel_id, dest_str, src_str, lsp_name ? lsp_name : "N/A");

    struct rsvp_path_key key;
    memset(&key, 0, sizeof(key));
    struct in_addr ext_id = *src;

    key.session.dest_addr = *dest;
    key.session.tunnel_id = htons(tunnel_id);
    key.session.extended_tunnel_id = ext_id;
    key.sender.source_addr = *src;
    key.sender.lsp_id = htons(next_lsp_id++);

    struct rsvp_psb* psb = rsvp_psb_find(&key);
    if (!psb) {
        LOG_DEBUG("  - Creating new PSB for initiated PATH");
        psb = rsvp_psb_create(&key);
        if (!psb) {
            LOG_ERROR("  - Failed to create PSB!");
            return;
        }
        psb->refresh_ms = RSVP_REFRESH_MS;
        psb->is_ingress = true;
        uint32_t refresh_ms = get_jittered_refresh(psb->refresh_ms, false);
        LOG_DEBUG("  - Starting Ingress Refresh Timer: %u ms", refresh_ms);
        rsvp_timer_start(&psb->refresh_timer,
            RSVP_TIMER_REFRESH, refresh_ms,
            psb_refresh_timer_cb, psb);
        psb->lsp_name = lsp_name ? strdup(lsp_name) : NULL;
    } else {
        LOG_DEBUG("  - PSB already exists for this tunnel.");
    }

    send_path_downstream(psb);
}

/**
 * @brief Teardown an existing LSP.
 * @details Looks up the LSP by tunnel ID and initiates a PathTear message.
 * @param [in] tunnel_id Tunnel ID of the LSP to teardown.
 */
void rsvp_teardown_path(uint16_t tunnel_id) {
    struct rsvp_psb* psb = rsvp_psb_find_by_id(tunnel_id);
    if (!psb) {
        printf("Tunnel ID %u not found.\n", tunnel_id);
        return;
    }

    printf("Tearing down tunnel %u...\n", tunnel_id);
    rsvp_psb_cleanup(psb, true);
}

static void psb_refresh_timer_cb(void* arg) {
    struct rsvp_psb* psb = (struct rsvp_psb*)arg;
    struct in_addr dest = psb->key.session.dest_addr;
    bool is_transit = (psb->prev_hop.neighbor_addr.s_addr != 0);
    
    char dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest, dest_str, sizeof(dest_str));

    LOG_DEBUG("PSB Refresh Timer Callback [Tunnel: %d, Dest: %s]",
              ntohs(psb->key.session.tunnel_id), dest_str);

    if (psb->is_ingress || !hal_netlink_is_local_addr(&dest)) {
        if (is_transit && !psb->is_ingress) {
            psb->refresh_count++;
            LOG_DEBUG("  - Transit PSB Refresh Count: %u", psb->refresh_count);
            if (psb->refresh_count > 2) {
                LOG_WARN("  - PSB missed %u refreshes, tearing down state", psb->refresh_count);
                rsvp_psb_cleanup(psb, true);
                return;
            }
        }
        LOG_INFO("  - Refreshing PATH downstream for Tunnel %d", ntohs(psb->key.session.tunnel_id));
        send_path_downstream(psb);
    }

    uint32_t next_refresh = get_jittered_refresh(psb->refresh_ms, is_transit && !psb->is_ingress);
    LOG_DEBUG("  - Rescheduling PSB Refresh: %u ms", next_refresh);
    rsvp_timer_start(&psb->refresh_timer,
        RSVP_TIMER_REFRESH, next_refresh, psb_refresh_timer_cb, psb);
}

static void psb_cleanup_timer_cb(void* arg) {
    struct rsvp_psb* psb = (struct rsvp_psb*)arg;
    LOG_WARN("PSB Cleanup Timer Expired [Tunnel: %d]: Tearing down state",
             ntohs(psb->key.session.tunnel_id));
    rsvp_psb_cleanup(psb, true);
}

static void rsb_refresh_timer_cb(void* arg) {
    struct rsvp_rsb* rsb = (struct rsvp_rsb*)arg;

    LOG_DEBUG("RSB Refresh Timer Callback [Tunnel: %d]", ntohs(rsb->key.session.tunnel_id));

    /* Check if we are Transit for this RSB */
    bool is_rsb_backup = false;
    if (rsb->associated_psb && rsb->associated_psb->key.session.dest_addr.s_addr != 0) {
        struct in_addr dest_addr = rsb->associated_psb->key.session.dest_addr;
        if (!hal_netlink_is_local_addr(&dest_addr)) {
            is_rsb_backup = true;
        }
    }

    if (rsb->associated_psb &&
        rsb->associated_psb->prev_hop.neighbor_addr.s_addr != 0 &&
        !rsb->associated_psb->is_ingress) {

        if (is_rsb_backup) {
            rsb->refresh_count++;
            LOG_DEBUG("  - Transit RSB Refresh Count: %u", rsb->refresh_count);
            if (rsb->refresh_count > 2) {
                LOG_WARN("  - RSB missed %u refreshes from downstream, tearing down state", rsb->refresh_count);
                rsvp_rsb_cleanup(rsb, true);
                return;
            }
        }

        LOG_INFO("  - Refreshing RESV upstream for Tunnel %d", ntohs(rsb->key.session.tunnel_id));
        send_resv_upstream(rsb);
    }

    uint32_t next_refresh = get_jittered_refresh(rsb->refresh_ms, is_rsb_backup);
    LOG_DEBUG("  - Rescheduling RSB Refresh: %u ms", next_refresh);
    rsvp_timer_start(&rsb->refresh_timer,
        RSVP_TIMER_REFRESH, next_refresh, rsb_refresh_timer_cb, rsb);
}

static void rsb_cleanup_timer_cb(void* arg) {
    struct rsvp_rsb* rsb = (struct rsvp_rsb*)arg;
    LOG_WARN("RSB Cleanup Timer Expired [Tunnel: %d]: Tearing down state",
             ntohs(rsb->key.session.tunnel_id));
    rsvp_rsb_cleanup(rsb, true);
}
