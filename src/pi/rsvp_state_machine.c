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
static void send_resv_upstream(struct rsvp_rsb *rsb);
static void propagate_path_tear(struct rsvp_psb *psb);
static void propagate_resv_tear(struct rsvp_rsb *rsb);

static void handle_path_message(struct rsvp_message_info *info) {
    printf("Handling PATH message...\n");
    struct rsvp_psb *psb = rsvp_psb_find(&info->key);
    struct in_addr next_hop = {0};

    if (!psb) {
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

    /* ERO Processing */
    if (info->ero) {
        next_hop = info->ero->addr;
        printf("Next hop from ERO: %s\n", inet_ntoa(next_hop));
        
        /* Transit: Forward downstream */
        printf("Transit: Forwarding PATH downstream to %s...\n", inet_ntoa(next_hop));
        rsvp_send_packet(&next_hop, (uint8_t *)info->common_hdr, ntohs(info->common_hdr->length));
    } else {
        /* Egress: Trigger RESV */
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
        rsvp_send_packet(&psb->prev_hop.neighbor_addr, (uint8_t *)info->common_hdr, ntohs(info->common_hdr->length));
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
    rsvp_builder_add_session_ipv4(&b, &psb->key.session.dest_addr, psb->key.session.tunnel_id, &psb->key.session.extended_tunnel_id);
    rsvp_builder_add_hop_ipv4(&b, &psb->prev_hop.neighbor_addr, psb->ifindex_in); /* Simple hop */
    rsvp_builder_add_time_values(&b, RSVP_REFRESH_MS);
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 1, &psb->key.sender, sizeof(psb->key.sender));
    rsvp_builder_add_label_ipv4(&b, rsb->label_in ? rsb->label_in : 3);

    size_t len = rsvp_builder_finalize(&b);
    rsvp_send_packet(&psb->prev_hop.neighbor_addr, buf, len);
}

static void propagate_path_tear(struct rsvp_psb *psb) {
    /* TODO: Forward PathTear downstream based on stored next-hop */
    printf("Propagating PathTear downstream...\n");
}

static void propagate_resv_tear(struct rsvp_rsb *rsb) {
    if (rsb->associated_psb) {
        printf("Propagating ResvTear upstream to %s...\n", inet_ntoa(rsb->associated_psb->prev_hop.neighbor_addr));
        /* TODO: Build and send ResvTear packet */
    }
}

void rsvp_initiate_path(struct in_addr *dest, uint16_t tunnel_id, struct in_addr *next_hop) {
    uint8_t buf[1024];
    struct rsvp_builder b;
    struct rsvp_path_key key;
    struct in_addr ext_id = {0};
    struct in_addr source = {0};

    printf("Initiating PATH for tunnel %d to %s via %s\n", 
           tunnel_id, inet_ntoa(*dest), inet_ntoa(*next_hop));

    memset(&key, 0, sizeof(key));
    key.session.dest_addr = *dest;
    key.session.tunnel_id = tunnel_id;
    key.session.extended_tunnel_id = ext_id;
    key.sender.source_addr = source; /* Should be our local addr */
    key.sender.lsp_id = 1;

    struct rsvp_psb *psb = rsvp_psb_find(&key);
    if (!psb) {
        psb = rsvp_psb_create(&key);
        if (!psb) return;
        psb->cleanup_timer_id = rsvp_timer_start(RSVP_TIMER_CLEANUP, RSVP_CLEANUP_MS, psb_cleanup_timer_cb, psb);
        psb->refresh_timer_id = rsvp_timer_start(RSVP_TIMER_REFRESH, RSVP_REFRESH_MS, psb_refresh_timer_cb, psb);
    }

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
    rsvp_builder_add_session_ipv4(&b, dest, tunnel_id, &ext_id);
    rsvp_builder_add_hop_ipv4(&b, &source, 0);
    rsvp_builder_add_time_values(&b, RSVP_REFRESH_MS);
    
    /* Sender Template */
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 1, &key.sender, sizeof(key.sender));
    
    /* ERO (Minimal) */
    struct rsvp_ero_ipv4_subobj ero;
    ero.type = 1;
    ero.length = 8;
    ero.addr = *next_hop;
    ero.prefix_len = 32;
    ero.res = 0;
    rsvp_builder_add_obj(&b, RSVP_CLASS_EXPLICIT_ROUTE, 1, &ero, sizeof(ero));

    size_t len = rsvp_builder_finalize(&b);
    rsvp_send_packet(next_hop, buf, len);
}

static void psb_refresh_timer_cb(void *arg) {
    struct rsvp_psb *psb = (struct rsvp_psb *)arg;
    psb->refresh_timer_id = rsvp_timer_start(RSVP_TIMER_REFRESH, RSVP_REFRESH_MS, psb_refresh_timer_cb, psb);
}

static void psb_cleanup_timer_cb(void *arg) {
    struct rsvp_psb *psb = (struct rsvp_psb *)arg;
    rsvp_timer_stop(psb->refresh_timer_id);
    if (psb->associated_rsb) rsvp_rsb_delete(psb->associated_rsb);
    rsvp_psb_delete(psb);
}
