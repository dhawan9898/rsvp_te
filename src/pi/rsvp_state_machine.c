#include "rsvp_state_machine.h"
#include "rsvp_state_db.h"
#include "rsvp_dispatcher.h"
#include "label_mgr.h"
#include "pi/rsvp_timers.h"
#include "pi/rsvp_builder.h"
#include "hal/hal_netlink.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define RSVP_REFRESH_MS 30000
#define RSVP_CLEANUP_MS 90000

/* Forward declarations */
static void psb_refresh_timer_cb(void *arg);
static void psb_cleanup_timer_cb(void *arg);
static void rsb_refresh_timer_cb(void *arg);
static void rsb_cleanup_timer_cb(void *arg);
static void send_resv_upstream(struct rsvp_rsb *rsb);
static void propagate_path_tear(struct rsvp_psb *psb);
static void propagate_resv_tear(struct rsvp_rsb *rsb);

static void handle_path_message(struct rsvp_message_info *info) {
    printf("Handling PATH message...\n");
    struct rsvp_psb *psb = rsvp_psb_find(&info->key);
    struct in_addr dest;
    bool is_new = (psb == NULL);

    if (is_new) {
        printf("New PATH: creating PSB\n");
        psb = rsvp_psb_create(&info->key);
        if (!psb) return;
        
        if (info->hop_v4) {
            psb->prev_hop = *info->hop_v4;
        }

        psb->cleanup_timer_id = rsvp_timer_start(RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS, psb_cleanup_timer_cb, psb);
        psb->refresh_timer_id = rsvp_timer_start(RSVP_TIMER_REFRESH, RSVP_REFRESH_MS, psb_refresh_timer_cb, psb);
    } else {
        printf("Refresh PATH: resetting cleanup timer\n");
        rsvp_timer_stop(psb->cleanup_timer_id);
        psb->cleanup_timer_id = rsvp_timer_start(RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS, psb_cleanup_timer_cb, psb);
    }

    dest = info->key.session.dest_addr;
    if (hal_netlink_is_local_addr(&dest)) {
        /* Egress: We are the tail-end. Triggering RESV... */
        printf("Egress: We are the tail-end. Triggering RESV...\n");
        struct rsvp_rsb *rsb = rsvp_rsb_find(&info->key);
        if (!rsb) {
            rsb = rsvp_rsb_create(&info->key);
            if (rsb) {
                rsb->associated_psb = psb;
                psb->associated_rsb = rsb;
                send_resv_upstream(rsb);
            }
        }
    } else {
        /* Transit node */
        struct in_addr next_hop = {0};
        
        int out_ifindex = hal_netlink_get_egress_if(&dest, &next_hop);
        
        if (out_ifindex < 0) {
            printf("Transit: No route to dest %s. Dropping PATH.\n", inet_ntoa(info->key.session.dest_addr));
            return;
        }

        printf("Transit: Forwarding PATH downstream to %s (via ifindex %d)...\n", inet_ntoa(next_hop), out_ifindex);
        
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
        info->common_hdr->checksum = rsvp_checksum((uint16_t *)info->common_hdr, ntohs(info->common_hdr->length) / 2);
        
        rsvp_send_packet(&next_hop, (uint8_t *)info->common_hdr, ntohs(info->common_hdr->length));
    }
}

static void handle_resv_message(struct rsvp_message_info *info) {
    printf("Handling RESV message...\n");
    struct rsvp_rsb *rsb = rsvp_rsb_find(&info->key);
    bool is_new = false;

    if (!rsb) {
        printf("New RESV: creating RSB\n");
        rsb = rsvp_rsb_create(&info->key);
        if (!rsb) return;
        is_new = true;
        
        struct rsvp_psb *psb = rsvp_psb_find(&info->key);
        if (psb) {
            rsb->associated_psb = psb;
            psb->associated_rsb = rsb;
        }
        
        rsb->cleanup_timer_id = rsvp_timer_start(RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS, rsb_cleanup_timer_cb, rsb);
        rsb->refresh_timer_id = rsvp_timer_start(RSVP_TIMER_REFRESH, RSVP_REFRESH_MS, rsb_refresh_timer_cb, rsb);
    } else {
        printf("Refresh RESV: resetting cleanup timer\n");
        rsvp_timer_stop(rsb->cleanup_timer_id);
        rsb->cleanup_timer_id = rsvp_timer_start(RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS, rsb_cleanup_timer_cb, rsb);
    }

    if (info->label) {
        rsb->label_out = ntohl(info->label->label);
    }

    if (is_new) {
        if (rsb->associated_psb && rsb->associated_psb->prev_hop.neighbor_addr.s_addr != 0) {
            rsb->label_in = label_mgr_alloc();
            printf("Transit: Forwarding RESV upstream to %s (label in: %u, out: %u)\n", 
                   inet_ntoa(rsb->associated_psb->prev_hop.neighbor_addr), rsb->label_in, rsb->label_out);
            send_resv_upstream(rsb);
        } else {
            printf("Ingress: Reservation complete for LSP %d\n", rsb->key.session.tunnel_id);
        }
    }
}

static void handle_path_tear(struct rsvp_message_info *info) {
    printf("Handling PathTear message...\n");
    struct rsvp_psb *psb = rsvp_psb_find(&info->key);
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

static void handle_resv_tear(struct rsvp_message_info *info) {
    printf("Handling ResvTear message...\n");
    struct rsvp_rsb *rsb = rsvp_rsb_find(&info->key);
    if (rsb) {
        propagate_resv_tear(rsb);
        
        if (rsb->label_in != 0) {
            label_mgr_free(rsb->label_in);
        }
        
        if (rsb->associated_psb) {
            rsb->associated_psb->associated_rsb = NULL;
        }
        
        rsvp_timer_stop(rsb->refresh_timer_id);
        rsvp_timer_stop(rsb->cleanup_timer_id);
        rsvp_rsb_delete(rsb);
    }
}

static void handle_path_err(struct rsvp_message_info *info) {
    printf("Handling PathErr message...\n");
    if (info->error_spec) {
        printf("PathErr: Code %d, Value %d from node %s\n", 
               info->error_spec->error_code, info->error_spec->error_value, 
               inet_ntoa(info->error_spec->error_node));
    }
    
    struct rsvp_psb *psb = rsvp_psb_find(&info->key);
    if (psb && psb->prev_hop.neighbor_addr.s_addr != 0) {
        printf("Propagating PathErr upstream to %s...\n", inet_ntoa(psb->prev_hop.neighbor_addr));
        struct in_addr prev_addr = psb->prev_hop.neighbor_addr;
        rsvp_send_packet(&prev_addr, (uint8_t *)info->common_hdr, ntohs(info->common_hdr->length));
    }
}

static void handle_resv_err(struct rsvp_message_info *info) {
    printf("Handling ResvErr message...\n");
    if (info->error_spec) {
        printf("ResvErr: Code %d, Value %d from node %s\n", 
               info->error_spec->error_code, info->error_spec->error_value, 
               inet_ntoa(info->error_spec->error_node));
    }
    
    /* ResvErr propagates downstream toward the egress */
    /* In a real implementation, we'd find the downstream neighbor from the RSB/PSB */
    printf("Propagating ResvErr downstream...\n");
}

void rsvp_handle_message(struct rsvp_message_info *info) {
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
            printf("Unsupported message type: %d\n", info->common_hdr->msg_type);
            break;
    }
}

static void send_resv_upstream(struct rsvp_rsb *rsb) {
    uint8_t buf[1024];
    struct rsvp_builder b;
    struct rsvp_psb *psb = rsb->associated_psb;
    if (!psb) return;

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESV);
    
    struct in_addr dest = psb->key.session.dest_addr;
    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;
    struct in_addr nbr = psb->prev_hop.neighbor_addr;

    rsvp_builder_add_session_ipv4(&b, &dest, psb->key.session.tunnel_id, &ext_dest);
    
    /* Calculate local IP for RESV HOP object */
    struct in_addr local_addr = {0};
    struct in_addr dummy_next_hop;
    int out_ifindex = hal_netlink_get_egress_if(&nbr, &dummy_next_hop);
    if (out_ifindex >= 0) {
        hal_netlink_get_local_addr(out_ifindex, &local_addr);
    }
    rsvp_builder_add_hop_ipv4(&b, &local_addr, out_ifindex >= 0 ? (uint32_t)out_ifindex : psb->ifindex_in);
    
    rsvp_builder_add_time_values(&b, RSVP_REFRESH_MS);
    
    /* STYLE object */
    rsvp_builder_add_style(&b, RSVP_STYLE_FF);
    
    /* FILTER_SPEC uses C-Type 7 for IPv4 LSP */
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7, &psb->key.sender, sizeof(psb->key.sender));
    rsvp_builder_add_label_ipv4(&b, rsb->label_in ? rsb->label_in : 3);

    size_t len = rsvp_builder_finalize(&b);
    struct in_addr nbr_addr = psb->prev_hop.neighbor_addr;
    rsvp_send_packet(&nbr_addr, buf, len);
}

static void propagate_path_tear(struct rsvp_psb *psb) {
    (void)psb;
    /* TODO: Forward PathTear downstream based on stored next-hop */
    printf("Propagating PathTear downstream...\n");
}

static void propagate_resv_tear(struct rsvp_rsb *rsb) {
    if (rsb->associated_psb) {
        printf("Propagating ResvTear upstream to %s...\n", inet_ntoa(rsb->associated_psb->prev_hop.neighbor_addr));
        /* TODO: Build and send ResvTear packet */
    } else {
        (void)rsb;
    }
}

void rsvp_initiate_path(struct in_addr *src, struct in_addr *dest, uint16_t tunnel_id, const char *lsp_name) {
    uint8_t buf[1024];
    struct rsvp_builder b;
    struct rsvp_path_key key;
    struct in_addr ext_id = *src; /* Extended tunnel ID is src_ip */
    struct in_addr next_hop = {0};

    int ifindex = hal_netlink_get_egress_if(dest, &next_hop);
    if (ifindex < 0) {
        printf("Failed to find route to dest %s\n", inet_ntoa(*dest));
        return;
    }

    char dest_str[INET_ADDRSTRLEN];
    char next_hop_str[INET_ADDRSTRLEN];
    strncpy(dest_str, inet_ntoa(*dest), INET_ADDRSTRLEN);
    strncpy(next_hop_str, inet_ntoa(next_hop), INET_ADDRSTRLEN);

    printf("Initiating PATH for tunnel %d (LSP: %s) to %s via %s (ifindex %d)\n", 
           tunnel_id, lsp_name ? lsp_name : "none", dest_str, next_hop_str, ifindex);

    memset(&key, 0, sizeof(key));
    key.session.dest_addr = *dest;
    key.session.tunnel_id = tunnel_id;
    key.session.extended_tunnel_id = ext_id;
    key.sender.source_addr = *src;
    key.sender.lsp_id = 1;

    struct rsvp_psb *psb = rsvp_psb_find(&key);
    if (!psb) {
        psb = rsvp_psb_create(&key);
        if (!psb) return;
        psb->cleanup_timer_id = rsvp_timer_start(RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS, psb_cleanup_timer_cb, psb);
        psb->refresh_timer_id = rsvp_timer_start(RSVP_TIMER_REFRESH, RSVP_REFRESH_MS, psb_refresh_timer_cb, psb);
        psb->ifindex_out = ifindex;
    }

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
    rsvp_builder_add_session_ipv4(&b, dest, tunnel_id, &ext_id);
    
    struct in_addr local_addr = {0};
    if (hal_netlink_get_local_addr(ifindex, &local_addr) < 0) {
        local_addr = *src; /* Fallback to src if local addr lookup fails */
    }
    rsvp_builder_add_hop_ipv4(&b, &local_addr, ifindex);
    rsvp_builder_add_time_values(&b, RSVP_REFRESH_MS);
    
    /* LABEL_REQUEST */
    rsvp_builder_add_label_request(&b, 0x0800); /* 0x0800 = IPv4 */
    
    /* SESSION_ATTRIBUTE */
    if (lsp_name) {
        rsvp_builder_add_session_attribute(&b, lsp_name);
    }
    
    /* Sender Template (C-Type 7 for IPv4 LSP) */
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7, &key.sender, sizeof(key.sender));
    
    /* SENDER_TSPEC */
    struct rsvp_sender_tspec tspec;
    memset(&tspec, 0, sizeof(tspec));
    tspec.version = 0;
    tspec.length = htons(7);
    tspec.service_hdr = 5; /* Controlled-Load */
    tspec.svc_length = htons(6);
    tspec.param_id = 127; /* Token Bucket */
    tspec.param_length = htons(5);
    tspec.token_bucket_rate = 1000000.0f;
    tspec.token_bucket_size = 1000.0f;
    tspec.peak_data_rate = 1000000.0f;
    tspec.min_policed_unit = htonl(64);
    tspec.max_packet_size = htonl(1500);
    rsvp_builder_add_tspec(&b, &tspec);

    /* ERO is omitted as per request: route using Netlink entirely */

    size_t len = rsvp_builder_finalize(&b);
    
    /* Send strictly hop-by-hop using the physical next hop IP */
    rsvp_send_packet(&next_hop, buf, len);
}

static void psb_refresh_timer_cb(void *arg) {
    struct rsvp_psb *psb = (struct rsvp_psb *)arg;
    psb->refresh_timer_id = rsvp_timer_start(RSVP_TIMER_REFRESH, RSVP_REFRESH_MS, psb_refresh_timer_cb, psb);
}

static void psb_cleanup_timer_cb(void *arg) {
    struct rsvp_psb *psb = (struct rsvp_psb *)arg;
    rsvp_timer_stop(psb->refresh_timer_id);
    if (psb->associated_rsb) {
        rsvp_timer_stop(psb->associated_rsb->refresh_timer_id);
        rsvp_timer_stop(psb->associated_rsb->cleanup_timer_id);
        rsvp_rsb_delete(psb->associated_rsb);
    }
    rsvp_psb_delete(psb);
}

static void rsb_refresh_timer_cb(void *arg) {
    struct rsvp_rsb *rsb = (struct rsvp_rsb *)arg;
    rsb->refresh_timer_id = rsvp_timer_start(RSVP_TIMER_REFRESH, RSVP_REFRESH_MS, rsb_refresh_timer_cb, rsb);
    if (rsb->associated_psb && rsb->associated_psb->prev_hop.neighbor_addr.s_addr != 0) {
        send_resv_upstream(rsb);
    }
}

static void rsb_cleanup_timer_cb(void *arg) {
    struct rsvp_rsb *rsb = (struct rsvp_rsb *)arg;
    rsvp_timer_stop(rsb->refresh_timer_id);
    if (rsb->associated_psb) rsb->associated_psb->associated_rsb = NULL;
    if (rsb->label_in != 0) label_mgr_free(rsb->label_in);
    rsvp_rsb_delete(rsb);
}
