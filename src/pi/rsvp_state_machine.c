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
#define RSVP_CLEANUP_MS(R) ((uint32_t)((RSVP_K_VALUE + 0.5) * (R)))

static uint16_t next_lsp_id = 1;

static uint32_t get_jittered_refresh(uint32_t base_ms) {
    if (base_ms == 0) base_ms = RSVP_REFRESH_MS;
    /* Set to a value T such that 0.5R <= T <= 1.5R */
    uint32_t min = base_ms / 2;
    uint32_t range = base_ms;
    if (range == 0) range = 1;
    return min + (rand() % range);
}

/* Forward declarations */
static void psb_refresh_timer_cb(void* arg);
static void psb_cleanup_timer_cb(void* arg);
static void rsb_refresh_timer_cb(void* arg);
static void rsb_cleanup_timer_cb(void* arg);
static void send_resv_upstream(struct rsvp_rsb* rsb);
static void propagate_path_tear(struct rsvp_psb* psb);
static void propagate_resv_tear(struct rsvp_rsb* rsb);
static void send_path_downstream(struct rsvp_psb* psb);

static void handle_path_message(struct rsvp_message_info* info) {
    LOG_INFO("Handling PATH message...");
    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    struct in_addr dest;
    bool is_new = (psb == NULL);

    if (is_new) {
        LOG_INFO("New PATH: creating PSB");
        psb = rsvp_psb_create(&info->key);
        if (!psb) return;
        psb->refresh_ms = RSVP_REFRESH_MS;
    }

    if (info->time_values) {
        psb->refresh_ms = ntohl(info->time_values->refresh_ms);
    }

    if (info->lsp_name[0] != '\0') {
        if (psb->lsp_name) free(psb->lsp_name);
        psb->lsp_name = strdup(info->lsp_name);
    }

    /* Reset Cleanup Timer */
    rsvp_timer_stop(psb->cleanup_timer_id);
    psb->cleanup_timer_id = rsvp_timer_start(
        RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS(psb->refresh_ms), psb_cleanup_timer_cb, psb);

    /* Refresh Timer: Restarted to jittered value */
    rsvp_timer_stop(psb->refresh_timer_id);
    psb->refresh_timer_id = rsvp_timer_start(
        RSVP_TIMER_REFRESH, get_jittered_refresh(psb->refresh_ms), psb_refresh_timer_cb, psb);

    if (info->hop_v4) {
        psb->prev_hop = *info->hop_v4;
        psb->ifindex_in = ntohl(info->hop_v4->logical_interface);
    }

    dest = info->key.session.dest_addr;
    if (hal_netlink_is_local_addr(&dest)) {
        /* Egress: We are the tail-end. Triggering RESV... */
        LOG_INFO("Egress: We are the tail-end. Triggering RESV...");
        struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
        if (!rsb) {
            rsb = rsvp_rsb_create(&info->key);
            if (rsb) {
                rsb->associated_psb = psb;
                psb->associated_rsb = rsb;
                rsb->refresh_ms = psb->refresh_ms;

                rsb->cleanup_timer_id = rsvp_timer_start(
                    RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS(rsb->refresh_ms), rsb_cleanup_timer_cb,
                    rsb);
                rsb->refresh_timer_id = rsvp_timer_start(
                    RSVP_TIMER_REFRESH, get_jittered_refresh(rsb->refresh_ms), rsb_refresh_timer_cb,
                    rsb);

                send_resv_upstream(rsb);
            }
        } else {
            rsb->refresh_ms = psb->refresh_ms;
        }
    } else {
        /* Transit node or Ingress receiving its own packet */
        struct in_addr src_addr = info->key.sender.source_addr;
        if (hal_netlink_is_local_addr(&src_addr)) {
            LOG_INFO(
                "Ingress: Received own PATH message back. Dropping to prevent "
                "loop.");
            return;
        }

        struct in_addr next_hop = {0};
        int out_ifindex = hal_netlink_get_egress_if(&dest, &next_hop);

        if (out_ifindex < 0) {
            LOG_INFO("Transit: No route to dest %s. Dropping PATH.",
                     inet_ntoa(info->key.session.dest_addr));
            return;
        }

        LOG_INFO(
            "Transit: Forwarding PATH downstream to %s (via ifindex %d)...",
            inet_ntoa(next_hop), out_ifindex);
        psb->ifindex_out = out_ifindex;

        if (info->hop_v4) {
            struct in_addr local_addr = {0};
            if (hal_netlink_get_local_addr(out_ifindex, &local_addr) == 0) {
                info->hop_v4->neighbor_addr = local_addr;
                info->hop_v4->logical_interface = htonl(out_ifindex);
            }
        }

        if (info->common_hdr->ttl > 0) {
            info->common_hdr->ttl--;
        }
        info->common_hdr->checksum = 0;
        info->common_hdr->checksum = rsvp_checksum(
            (uint16_t*)info->common_hdr, ntohs(info->common_hdr->length));

        /* Forward PATH directly to session destination with RAO */
        struct in_addr src_ip = info->key.sender.source_addr;
        rsvp_send_packet(&src_ip, &dest, (uint8_t*)info->common_hdr,
                         ntohs(info->common_hdr->length), true);
    }
}

static void handle_resv_message(struct rsvp_message_info* info) {
    LOG_INFO("Handling RESV message...");
    struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
    bool is_new = (rsb == NULL);

    if (is_new) {
        LOG_INFO("New RESV: creating RSB");
        rsb = rsvp_rsb_create(&info->key);
        if (!rsb) return;
        rsb->refresh_ms = RSVP_REFRESH_MS;

        struct rsvp_psb* psb = rsvp_psb_find(&info->key);
        if (psb) {
            rsb->associated_psb = psb;
            psb->associated_rsb = rsb;
            rsb->refresh_ms = psb->refresh_ms;
        }
    }

    if (info->time_values) {
        rsb->refresh_ms = ntohl(info->time_values->refresh_ms);
    }

    /* Reset Cleanup Timer */
    rsvp_timer_stop(rsb->cleanup_timer_id);
    rsb->cleanup_timer_id = rsvp_timer_start(
        RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS(rsb->refresh_ms), rsb_cleanup_timer_cb, rsb);

    /* Refresh Timer: Restarted to jittered value */
    rsvp_timer_stop(rsb->refresh_timer_id);
    rsb->refresh_timer_id = rsvp_timer_start(
        RSVP_TIMER_REFRESH, get_jittered_refresh(rsb->refresh_ms), rsb_refresh_timer_cb, rsb);

    if (info->label) {
        rsb->label_out = ntohl(info->label->label) >> 12;
    }

    if (info->hop_v4) {
        rsb->next_hop = *info->hop_v4;
    }

    if (is_new ||
        (info->label && rsb->label_out != (ntohl(info->label->label) >> 12))) {
        if (rsb->associated_psb) {
            struct rsvp_psb* psb = rsb->associated_psb;
            struct in_addr next_hop_addr = rsb->next_hop.neighbor_addr;
            if (psb->prev_hop.neighbor_addr.s_addr != 0) {
                /* Transit node */
                if (rsb->label_in == 0) rsb->label_in = label_mgr_alloc();
                LOG_INFO("Transit: Programming MPLS swap %u -> %u via if %u",
                         rsb->label_in, rsb->label_out,
                         ntohl(rsb->next_hop.logical_interface));
                hal_mpls_install(rsb->label_in, rsb->label_out,
                                 ntohl(rsb->next_hop.logical_interface),
                                 &next_hop_addr);
                if (is_new) {
                    LOG_INFO("Transit: Forwarding RESV upstream to %s",
                             inet_ntoa(psb->prev_hop.neighbor_addr));
                    send_resv_upstream(rsb);
                }
            } else {
                /* Ingress node */
                LOG_INFO("Ingress: Programming MPLS push %u via if %u",
                         rsb->label_out,
                         ntohl(rsb->next_hop.logical_interface));
                hal_mpls_install(0, rsb->label_out,
                                 ntohl(rsb->next_hop.logical_interface),
                                 &next_hop_addr);
                LOG_INFO("Ingress: Reservation complete for LSP %d",
                         ntohs(rsb->key.session.tunnel_id));
            }
        }
    }
}

static void handle_path_tear(struct rsvp_message_info* info) {
    LOG_INFO("Handling PathTear message...");
    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    if (psb) {
        propagate_path_tear(psb);

        /* If associated RSB exists, it should also be torn down or notified */
        if (psb->associated_rsb) {
            rsvp_timer_stop(psb->associated_rsb->refresh_timer_id);
            rsvp_timer_stop(psb->associated_rsb->cleanup_timer_id);
            rsvp_rsb_delete(psb->associated_rsb);
        }

        rsvp_timer_stop(psb->refresh_timer_id);
        rsvp_timer_stop(psb->cleanup_timer_id);
        rsvp_psb_delete(psb);
    }
}

static void handle_resv_tear(struct rsvp_message_info* info) {
    LOG_INFO("Handling ResvTear message...");
    struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
    if (rsb) {
        propagate_resv_tear(rsb);

        if (rsb->label_in != 0) {
            hal_mpls_remove(rsb->label_in);
            label_mgr_free(rsb->label_in);
        } else {
            /* Ingress */
            hal_mpls_remove(0);
        }

        if (rsb->associated_psb) {
            rsb->associated_psb->associated_rsb = NULL;
        }

        rsvp_timer_stop(rsb->refresh_timer_id);
        rsvp_timer_stop(rsb->cleanup_timer_id);
        rsvp_rsb_delete(rsb);
    }
}

static void handle_path_err(struct rsvp_message_info* info) {
    LOG_INFO("Handling PathErr message...");
    if (info->error_spec) {
        LOG_INFO("PathErr: Code %d, Value %d from node %s",
                 info->error_spec->error_code, info->error_spec->error_value,
                 inet_ntoa(info->error_spec->error_node));
    }

    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    if (psb && psb->prev_hop.neighbor_addr.s_addr != 0) {
        LOG_INFO("Propagating PathErr upstream to %s...",
                 inet_ntoa(psb->prev_hop.neighbor_addr));
        struct in_addr prev_addr = psb->prev_hop.neighbor_addr;
        struct in_addr local_addr = {0};
        struct in_addr dummy;
        int out_ifindex = hal_netlink_get_egress_if(&prev_addr, &dummy);
        if (out_ifindex >= 0) {
            hal_netlink_get_local_addr(out_ifindex, &local_addr);
        }

        if (info->common_hdr->ttl > 0) {
            info->common_hdr->ttl--;
        }
        info->common_hdr->checksum = 0;
        info->common_hdr->checksum =
            rsvp_checksum(info->common_hdr, ntohs(info->common_hdr->length));
        rsvp_send_packet(&local_addr, &prev_addr, (uint8_t*)info->common_hdr,
                         ntohs(info->common_hdr->length), false);
    }
}

static void handle_resv_err(struct rsvp_message_info* info) {
    LOG_INFO("Handling ResvErr message...");
    if (info->error_spec) {
        LOG_INFO("ResvErr: Code %d, Value %d from node %s",
                 info->error_spec->error_code, info->error_spec->error_value,
                 inet_ntoa(info->error_spec->error_node));
    }

    /* ResvErr propagates downstream toward the egress */
    /* In a real implementation, we'd find the downstream neighbor from the
     * RSB/PSB */
    LOG_INFO("Propagating ResvErr downstream...");
}

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
    if (!psb) return;

    if (rsb->label_in == 0) {
        rsb->label_in = label_mgr_alloc();
        if (rsb->label_in == 0) {
            LOG_INFO("send_resv_upstream: failed to allocate label_in");
            return;
        }
    }

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESV);

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
    rsvp_send_packet(&local_addr, &nbr_addr, buf, len, false);
}

static void propagate_path_tear(struct rsvp_psb* psb) {
    struct rsvp_session_ipv4 session = psb->key.session;
    struct in_addr dest_addr = session.dest_addr;
    struct in_addr ext_dest = session.extended_tunnel_id;
    struct in_addr next_hop = {0};
    int out_ifindex = hal_netlink_get_egress_if(&dest_addr, &next_hop);
    if (out_ifindex < 0) {
        LOG_INFO("Propagate PathTear: no route to dest %s",
                 inet_ntoa(dest_addr));
        return;
    }

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATHTEAR);
    rsvp_builder_add_session_ipv4(&b, &dest_addr, ntohs(session.tunnel_id),
                                  &ext_dest);

    struct in_addr local_addr = {0};
    if (hal_netlink_get_local_addr(out_ifindex, &local_addr) == 0) {
        rsvp_builder_add_hop_ipv4(&b, &local_addr, out_ifindex);
    }
    size_t len = rsvp_builder_finalize(&b);
    struct in_addr src_ip = psb->key.sender.source_addr;
    rsvp_send_packet(&src_ip, &dest_addr, buf, len, true);
}

static void propagate_resv_tear(struct rsvp_rsb* rsb) {
    if (!rsb->associated_psb) {
        return;
    }

    struct rsvp_psb* psb = rsb->associated_psb;
    struct rsvp_session_ipv4 session = psb->key.session;
    struct rsvp_hop_ipv4 prev_hop = psb->prev_hop;
    struct in_addr dest_addr = session.dest_addr;
    struct in_addr ext_dest = session.extended_tunnel_id;
    struct in_addr prev_neighbor = prev_hop.neighbor_addr;

    if (prev_neighbor.s_addr == 0) {
        LOG_INFO("Propagate ResvTear: no upstream neighbor");
        return;
    }

    LOG_INFO("Propagating ResvTear upstream to %s...",
             inet_ntoa(prev_neighbor));

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESVTEAR);
    rsvp_builder_add_session_ipv4(&b, &dest_addr, ntohs(session.tunnel_id),
                                  &ext_dest);
    rsvp_builder_add_hop_ipv4(&b, &prev_neighbor,
                              ntohl(prev_hop.logical_interface));
    rsvp_builder_add_time_values(&b, rsb->refresh_ms);
    size_t len = rsvp_builder_finalize(&b);

    struct in_addr local_addr = {0};
    struct in_addr dummy;
    int ifindex = hal_netlink_get_egress_if(&prev_neighbor, &dummy);
    if (ifindex >= 0) {
        hal_netlink_get_local_addr(ifindex, &local_addr);
    }
    rsvp_send_packet(&local_addr, &prev_neighbor, buf, len, false);
}

static void send_path_downstream(struct rsvp_psb* psb) {
    uint8_t buf[1024];
    struct rsvp_builder b;
    struct in_addr dest_addr = psb->key.session.dest_addr;
    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;
    struct in_addr next_hop = {0};

    int ifindex = hal_netlink_get_egress_if(&dest_addr, &next_hop);
    if (ifindex < 0) {
        LOG_INFO("send_path_downstream: no route to %s", inet_ntoa(dest_addr));
        return;
    }
    psb->ifindex_out = ifindex;

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
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

    /* In a real implementation, we'd add SESSION_ATTRIB from the PSB */
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
    struct in_addr src_ip = psb->key.sender.source_addr;
    rsvp_send_packet(&src_ip, &dest_addr, buf, len, true);
}

void rsvp_initiate_path(struct in_addr* src, struct in_addr* dest,
                        uint16_t tunnel_id, const char* lsp_name) {
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
        psb = rsvp_psb_create(&key);
        if (!psb) return;
        psb->refresh_ms = RSVP_REFRESH_MS;
        psb->cleanup_timer_id = rsvp_timer_start(
            RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS(psb->refresh_ms),
            psb_cleanup_timer_cb, psb);
        psb->refresh_timer_id = rsvp_timer_start(
            RSVP_TIMER_REFRESH, get_jittered_refresh(psb->refresh_ms),
            psb_refresh_timer_cb, psb);
        psb->lsp_name = lsp_name ? strdup(lsp_name) : NULL;
    }

    send_path_downstream(psb);
}

static void psb_refresh_timer_cb(void* arg) {
    struct rsvp_psb* psb = (struct rsvp_psb*)arg;
    struct in_addr dest = psb->key.session.dest_addr;

    if (!hal_netlink_is_local_addr(&dest)) {
        LOG_INFO("PSB Refresh Timer Expired: Refreshing PATH downstream...");
        send_path_downstream(psb);
    }

    psb->refresh_timer_id = rsvp_timer_start(
        RSVP_TIMER_REFRESH, get_jittered_refresh(psb->refresh_ms),
        psb_refresh_timer_cb, psb);
}

static void psb_cleanup_timer_cb(void* arg) {
    struct rsvp_psb* psb = (struct rsvp_psb*)arg;
    LOG_INFO("PSB Cleanup Timer Expired: Tearing down state");
    propagate_path_tear(psb);

    rsvp_timer_stop(psb->refresh_timer_id);
    if (psb->associated_rsb) {
        rsvp_timer_stop(psb->associated_rsb->refresh_timer_id);
        rsvp_timer_stop(psb->associated_rsb->cleanup_timer_id);
        rsvp_rsb_delete(psb->associated_rsb);
    }
    rsvp_psb_delete(psb);
}

static void rsb_refresh_timer_cb(void* arg) {
    struct rsvp_rsb* rsb = (struct rsvp_rsb*)arg;

    if (rsb->associated_psb &&
        rsb->associated_psb->prev_hop.neighbor_addr.s_addr != 0) {
        LOG_INFO("RSB Refresh Timer Expired: Refreshing RESV upstream...");
        send_resv_upstream(rsb);
    }

    rsb->refresh_timer_id = rsvp_timer_start(
        RSVP_TIMER_REFRESH, get_jittered_refresh(rsb->refresh_ms),
        rsb_refresh_timer_cb, rsb);
}

static void rsb_cleanup_timer_cb(void* arg) {
    struct rsvp_rsb* rsb = (struct rsvp_rsb*)arg;
    LOG_INFO("RSB Cleanup Timer Expired: Tearing down state");
    propagate_resv_tear(rsb);

    rsvp_timer_stop(rsb->refresh_timer_id);
    if (rsb->associated_psb) rsb->associated_psb->associated_rsb = NULL;
    if (rsb->label_in != 0) {
        hal_mpls_remove(rsb->label_in);
        label_mgr_free(rsb->label_in);
    } else {
        hal_mpls_remove(0);
    }
    rsvp_rsb_delete(rsb);
}
