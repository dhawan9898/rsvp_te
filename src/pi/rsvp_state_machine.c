/**
 * @file rsvp_state_machine.c
 * @brief RSVP-TE State Machine — message processing, ERO routing, and FRR.
 *
 * Responsibilities:
 *   - Process all RSVP message types (PATH, RESV, PathTear, ResvTear,
 *     PathErr, ResvErr, ResvConf, SRefresh).
 *   - Route PATH messages hop-by-hop using the ERO next-hop address as the
 *     IP destination (RFC 3209 §4.1).
 *   - Maintain RFC 2205 §3.7 state lifetimes: (K + 0.5) × R.
 *   - Implement RFC 4090 Fast ReRoute facility-backup mode.
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

/* ---- Timing constants --------------------------------------------------- */

#define RSVP_REFRESH_MS   30000u  /* Default refresh period R (ms) */
#define RSVP_K_VALUE      3u      /* Missed-refresh multiplier K */

/* RFC 2205 §3.7: state lifetime = (K + 0.5) × R.
 * Using K*R (without the 0.5) causes premature teardown under normal jitter
 * because the worst-case inter-refresh gap can reach 2.4R with ±20% jitter.
 */
#define RSVP_CLEANUP_MS(R) ((uint32_t)(((RSVP_K_VALUE) + 0.5f) * (R)))

/* ---- Module state ------------------------------------------------------- */

static uint16_t next_lsp_id = 1;

/* ---- Forward declarations ----------------------------------------------- */

static void psb_refresh_timer_cb(void* arg);
static void psb_cleanup_timer_cb(void* arg);
static void rsb_refresh_timer_cb(void* arg);
static void rsb_cleanup_timer_cb(void* arg);
static void send_resv_upstream(struct rsvp_rsb* rsb);
static void propagate_path_tear(struct rsvp_psb* psb);
static void propagate_resv_tear(struct rsvp_rsb* rsb);
static void propagate_resv_err(struct rsvp_rsb* rsb,
                                struct rsvp_error_spec_ipv4* err_spec);
static void send_path_downstream(struct rsvp_psb* psb);
static void rsvp_psb_cleanup(struct rsvp_psb* psb, bool propagate);
static void rsvp_rsb_cleanup(struct rsvp_rsb* rsb, bool propagate);

/* ---- Internal helpers --------------------------------------------------- */

/* Compute a jittered refresh interval.
 * Ingress/egress (is_backup=false): 0.8R … 1.2R  (RFC 2205 §3.7 trigger).
 * Transit (is_backup=true):          1.1R … 1.3R  (avoids unnecessary floods).
 */
static uint32_t get_jittered_refresh(uint32_t base_ms, bool is_backup) {
    if (base_ms == 0) base_ms = RSVP_REFRESH_MS;

    uint32_t lo, hi;
    if (is_backup) {
        lo = (uint32_t)(base_ms * 1.1f);
        hi = (uint32_t)(base_ms * 1.3f);
    } else {
        lo = (uint32_t)(base_ms * 0.8f);
        hi = (uint32_t)(base_ms * 1.2f);
    }
    uint32_t range = (hi > lo) ? (hi - lo) : 1u;
    return lo + (rand() % range);
}

/* Copy a SENDER_TSPEC from wire format (network byte order) to host order. */
static void tspec_copy_and_ntoh(struct rsvp_sender_tspec* dst,
                                 const struct rsvp_sender_tspec* src) {
    memcpy(dst, src, sizeof(*dst));

    uint32_t tmp;
    memcpy(&tmp, &src->token_bucket_rate,  4); dst->token_bucket_rate  = rsvp_net_to_float(tmp);
    memcpy(&tmp, &src->token_bucket_size,  4); dst->token_bucket_size  = rsvp_net_to_float(tmp);
    memcpy(&tmp, &src->peak_data_rate,     4); dst->peak_data_rate     = rsvp_net_to_float(tmp);
    dst->min_policed_unit = ntohl(src->min_policed_unit);
    dst->max_packet_size  = ntohl(src->max_packet_size);
}

/* Resolve the ERO-directed next hop for a PSB.
 * Returns the IP address that the PATH packet should be addressed to and
 * sets *out_ifindex to the resolved egress interface.
 *
 * RFC 3209 §4.1: the IP destination of a PATH message is the address of
 * the next RSVP-capable node along the explicit route, not the tunnel endpoint.
 * If the first ERO hop is the local node it is popped first.
 */
static struct in_addr resolve_path_next_hop(struct rsvp_psb* psb,
                                             int* out_ifindex) {
    struct in_addr ip_dest = psb->key.session.dest_addr; /* fallback */
    *out_ifindex = -1;

    if (psb->ero_count > 0) {
        struct in_addr local_addr = {0};
        hal_netlink_get_local_addr(0, &local_addr);

        /* Pop the first ERO hop if it is this node. */
        if (psb->ero[0].addr.s_addr == local_addr.s_addr) {
            char hop_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &psb->ero[0].addr, hop_str, sizeof(hop_str));
            LOG_DEBUG("  - ERO: Popping local hop %s", hop_str);
            memmove(&psb->ero[0], &psb->ero[1],
                    (psb->ero_count - 1) * sizeof(struct rsvp_ero_ipv4_subobj));
            psb->ero_count--;
        }

        if (psb->ero_count > 0) {
            /* Use the first remaining ERO hop as the IP destination.
             * For a strict hop the packet must arrive directly at that address.
             * For a loose hop we route toward it via IGP.
             */
            ip_dest = psb->ero[0].addr;
            bool is_loose = (psb->ero[0].type & RSVP_ERO_LOOSE) != 0;

            char ero_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_dest, ero_str, sizeof(ero_str));
            LOG_DEBUG("  - ERO: Next hop %s (%s)", ero_str,
                      is_loose ? "loose" : "strict");
        }
    }

    struct in_addr gw = {0};
    *out_ifindex = hal_netlink_get_egress_if(&ip_dest, &gw);

    /* For strict ERO hops the gateway IS the ERO address; for loose hops or
     * IGP routing the kernel fills in the actual L3 next hop.  Either way we
     * return ip_dest as the IP destination of the PATH packet. */
    return ip_dest;
}

/* ---- PathErr / ResvErr senders ------------------------------------------ */

static void send_path_err(struct rsvp_message_info* info,
                           uint8_t error_code, uint16_t error_value) {
    char src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->src_ip, src_str, sizeof(src_str));
    LOG_INFO("  - Sending PathErr to %s [Code: %d, Value: %d]",
             src_str, error_code, error_value);

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATHERR);
    b.hdr->ttl = 255;

    struct in_addr dest    = info->key.session.dest_addr;
    struct in_addr ext_dest = info->key.session.extended_tunnel_id;
    rsvp_builder_add_session_ipv4(&b, &dest,
                                   ntohs(info->key.session.tunnel_id),
                                   &ext_dest);

    struct rsvp_error_spec_ipv4 err;
    memset(&err, 0, sizeof(err));
    hal_netlink_get_local_addr(0, &err.error_node);
    err.error_code  = error_code;
    err.error_value = htons(error_value);
    rsvp_builder_add_obj(&b, RSVP_CLASS_ERROR_SPEC, 1, &err, sizeof(err));

    /* RFC 2205 §3.3.2: PathErr carries SENDER_TEMPLATE. */
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7,
                         &info->key.sender, sizeof(info->key.sender));

    size_t len = rsvp_builder_finalize(&b);
    struct in_addr zero = {0};
    rsvp_send_packet(&zero, &info->src_ip, buf, len, false);
}

static void send_resv_err(struct rsvp_message_info* info,
                           uint8_t error_code, uint16_t error_value) {
    char src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->src_ip, src_str, sizeof(src_str));
    LOG_INFO("  - Sending ResvErr to %s [Code: %d, Value: %d]",
             src_str, error_code, error_value);

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESVERR);
    b.hdr->ttl = 255;

    struct in_addr dest     = info->key.session.dest_addr;
    struct in_addr ext_dest = info->key.session.extended_tunnel_id;
    rsvp_builder_add_session_ipv4(&b, &dest,
                                   ntohs(info->key.session.tunnel_id),
                                   &ext_dest);

    struct rsvp_error_spec_ipv4 err;
    memset(&err, 0, sizeof(err));
    hal_netlink_get_local_addr(0, &err.error_node);
    err.error_code  = error_code;
    err.error_value = htons(error_value);
    rsvp_builder_add_obj(&b, RSVP_CLASS_ERROR_SPEC, 1, &err, sizeof(err));

    rsvp_builder_add_style(&b, RSVP_STYLE_FF);
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7,
                         &info->key.sender, sizeof(info->key.sender));

    size_t len = rsvp_builder_finalize(&b);
    struct in_addr zero = {0};
    rsvp_send_packet(&zero, &info->src_ip, buf, len, false);
}

/* ---- PATH message validation -------------------------------------------- */

static rsvp_error_t rsvp_validate_path_message(struct rsvp_message_info* info,
                                                struct rsvp_psb* existing_psb,
                                                uint8_t* err_code,
                                                uint16_t* err_val) {
    if (!info->hop_v4) {
        LOG_WARN("  - Validation: PATH missing mandatory RSVP_HOP object");
        /* Error code 6 = "Unknown Object Class" is wrong here; RFC 2205 §3.1
         * would use a format error.  We use routing-problem as best fit. */
        *err_code = RSVP_PROTO_ERR_ROUTING_PROBLEM;
        *err_val  = 0;
        return RSVP_ERR_MALFORMED_OBJ;
    }

    if (!info->sender_v4) {
        LOG_WARN("  - Validation: PATH missing mandatory SENDER_TEMPLATE object");
        *err_code = RSVP_PROTO_ERR_ROUTING_PROBLEM;
        *err_val  = 0;
        return RSVP_ERR_MALFORMED_OBJ;
    }

    if (!info->label_req && !existing_psb) {
        LOG_WARN("  - Validation: New PATH missing LABEL_REQUEST object (mandatory for RSVP-TE)");
        *err_code = RSVP_PROTO_ERR_ROUTING_PROBLEM;
        *err_val  = 0;
        return RSVP_ERR_MALFORMED_OBJ;
    }

    return RSVP_SUCCESS;
}

/* ---- RESV message validation -------------------------------------------- */

static rsvp_error_t rsvp_validate_resv_message(struct rsvp_message_info* info,
                                                struct rsvp_rsb* existing_rsb,
                                                uint8_t* err_code,
                                                uint16_t* err_val) {
    (void)existing_rsb;

    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    if (!psb) {
        LOG_WARN("  - Validation: No matching PSB for RESV "
                 "[TunnelID: %d] — sending ResvErr code 3 (No PATH State)",
                 ntohs(info->key.session.tunnel_id));
        *err_code = RSVP_PROTO_ERR_NO_PATH_STATE;
        *err_val  = 0;
        return RSVP_ERR_NOT_FOUND;
    }

    if (!info->hop_v4) {
        LOG_WARN("  - Validation: RESV missing mandatory RSVP_HOP object");
        *err_code = RSVP_PROTO_ERR_ROUTING_PROBLEM;
        *err_val  = 0;
        return RSVP_ERR_MALFORMED_OBJ;
    }

    if (!info->label) {
        LOG_WARN("  - Validation: RESV missing mandatory LABEL object");
        *err_code = RSVP_PROTO_ERR_ROUTING_PROBLEM;
        *err_val  = 0;
        return RSVP_ERR_MALFORMED_OBJ;
    }

    return RSVP_SUCCESS;
}

/* ---- Blockade (RFC 2209) ------------------------------------------------- */

static bool is_flowspec_gte(const struct rsvp_sender_tspec* a,
                             const struct rsvp_sender_tspec* b) {
    return (a->token_bucket_rate >= b->token_bucket_rate &&
            a->token_bucket_size >= b->token_bucket_size);
}

static bool rsvp_is_blockaded(struct rsvp_rsb* rsb) {
    struct rsvp_bsb* bsb = rsvp_bsb_find(&rsb->key);
    if (!bsb) return false;

    /* RFC 2209 rule B1: blockaded if RSB flowspec ≥ BSB.Qb */
    if (is_flowspec_gte(&rsb->flowspec, &bsb->flowspec_qb)) {
        LOG_WARN("  - RSB [TunnelID: %d] is BLOCKADED by BSB "
                 "(Qb rate: %.2f bytes/s)",
                 ntohs(rsb->key.session.tunnel_id),
                 bsb->flowspec_qb.token_bucket_rate);
        return true;
    }
    return false;
}

/* ---- Flowspec merging ---------------------------------------------------- */

static void rsvp_compute_merged_flowspec(struct rsvp_psb* psb,
                                          struct rsvp_sender_tspec* merged) {
    memset(merged, 0, sizeof(*merged));
    merged->service_hdr  = 5;  /* Controlled-Load */
    merged->svc_length   = 6;
    merged->param_id     = 127;
    merged->param_length = 5;
    merged->length       = (uint16_t)((sizeof(*merged) / 4) - 1);

    if (psb->associated_rsb && !rsvp_is_blockaded(psb->associated_rsb)) {
        struct rsvp_rsb* rsb = psb->associated_rsb;
        /* Single-RSB case: LUB is the RSB's own flowspec. */
        merged->token_bucket_rate = rsb->flowspec.token_bucket_rate;
        merged->token_bucket_size = rsb->flowspec.token_bucket_size;
        merged->peak_data_rate    = rsb->flowspec.peak_data_rate;
        merged->min_policed_unit  = rsb->flowspec.min_policed_unit;
        merged->max_packet_size   = rsb->flowspec.max_packet_size;
    } else {
        LOG_DEBUG("  - Flowspec merge: RSB for Tunnel %d is blockaded or absent, "
                  "using zero flowspec",
                  ntohs(psb->key.session.tunnel_id));
    }
}

/* ---- PATH downstream ---------------------------------------------------- */

/* Build and send a PATH message downstream.
 *
 * RFC 2205/3209 PATH message object order:
 *   SESSION, RSVP_HOP, TIME_VALUES, [EXPLICIT_ROUTE], LABEL_REQUEST,
 *   [SESSION_ATTRIBUTE], SENDER_TEMPLATE, SENDER_TSPEC, [ADSPEC],
 *   [RECORD_ROUTE]
 *
 * RFC 3209 §4.1: the IP destination is the first ERO hop address (strict or
 * loose), not the tunnel endpoint.  This ensures the PATH is delivered to the
 * correct next-hop node without relying on the IP routing table to reach the
 * ultimate destination.
 */
static void send_path_downstream(struct rsvp_psb* psb) {
    char dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &psb->key.session.dest_addr, dest_str, sizeof(dest_str));

    int ifindex = -1;
    struct in_addr ip_dest = resolve_path_next_hop(psb, &ifindex);

    if (ifindex < 0) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_dest, ip_str, sizeof(ip_str));
        LOG_ERROR("send_path_downstream: No route to next hop %s "
                  "(Tunnel %d, Dest %s)",
                  ip_str, ntohs(psb->key.session.tunnel_id), dest_str);
        return;
    }
    psb->ifindex_out = (uint32_t)ifindex;

    struct in_addr local_addr = {0};
    if (hal_netlink_get_local_addr(ifindex, &local_addr) < 0) {
        /* Fallback: use sender source address when local address lookup fails. */
        local_addr = psb->key.sender.source_addr;
    }

    char nh_str[INET_ADDRSTRLEN], local_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_dest,    nh_str,    sizeof(nh_str));
    inet_ntop(AF_INET, &local_addr, local_str, sizeof(local_str));
    LOG_DEBUG("  - PATH downstream: LocalSrc %s → NextHop %s, IfIndex %d",
              local_str, nh_str, ifindex);

    uint8_t buf[1500];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATH);
    b.hdr->ttl = (psb->ttl > 0) ? psb->ttl - 1 : 255;

    struct in_addr dest     = psb->key.session.dest_addr;
    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;

    /* 1. SESSION */
    rsvp_builder_add_session_ipv4(&b, &dest,
                                   ntohs(psb->key.session.tunnel_id),
                                   &ext_dest);

    /* 2. RSVP_HOP */
    rsvp_builder_add_hop_ipv4(&b, &local_addr, (uint32_t)ifindex);

    /* 3. TIME_VALUES */
    rsvp_builder_add_time_values(&b, psb->refresh_ms);

    /* 4. EXPLICIT_ROUTE (if hops remain after popping local node) */
    if (psb->ero_count > 0) {
        rsvp_builder_add_ero(&b, psb->ero, psb->ero_count);
    }

    /* 5. LABEL_REQUEST — mandatory for RSVP-TE (RFC 3209 §4.1) */
    rsvp_builder_add_label_request(&b, 0x0800 /* IPv4 */);

    /* 6. SESSION_ATTRIBUTE — include FRR flags if FRR is requested */
    uint8_t sa_flags = RSVP_SESSATTR_LOCAL_PROT_DESIRED | RSVP_SESSATTR_SE_STYLE;
    if (psb->frr_active) {
        sa_flags |= RSVP_SESSATTR_LOCAL_PROT_IN_USE;
        if (psb->frr_mode == RSVP_FRR_FACILITY) {
            sa_flags |= RSVP_SESSATTR_BW_PROTECTION;
        }
    }
    rsvp_builder_add_session_attribute_ex(&b, psb->lsp_name,
                                           psb->setup_prio,
                                           psb->holding_prio,
                                           sa_flags);

    /* 7. FAST_REROUTE — request FRR protection at each PLR (facility backup).
     *    Only included if this LSP has FRR enabled and is not itself a bypass. */
    if (psb->frr_mode != RSVP_FRR_NONE && !psb->is_bypass_tunnel) {
        rsvp_builder_add_fast_reroute(&b,
                                       psb->setup_prio, psb->holding_prio,
                                       32 /* hop limit */,
                                       RSVP_FRR_FLAG_FACILITY,
                                       (float)psb->frr_bandwidth);
    }

    /* 8. SENDER_TEMPLATE — must precede SENDER_TSPEC (RFC 2205 §3.1.3) */
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7,
                         &psb->key.sender, sizeof(psb->key.sender));

    /* 9. SENDER_TSPEC */
    struct rsvp_sender_tspec tspec = psb->tspec;
    if (tspec.token_bucket_rate == 0.0f) {
        /* PSB has no tspec yet (ingress-initiated); use a default 1 Mbps spec. */
        tspec.version        = 0;
        tspec.length         = (uint16_t)((sizeof(tspec) / 4) - 1);
        tspec.service_hdr    = 5;   /* Controlled-Load */
        tspec.svc_length     = 6;
        tspec.param_id       = 127;
        tspec.param_length   = 5;
        tspec.token_bucket_rate = 1000000.0f; /* 1 Mbps */
        tspec.token_bucket_size = 1000.0f;
        tspec.peak_data_rate    = 1000000.0f;
        tspec.min_policed_unit  = 64;
        tspec.max_packet_size   = 1500;
    }
    rsvp_builder_add_tspec(&b, &tspec);

    /* 10. RECORD_ROUTE — append local node and forward the accumulated RRO */
    struct rsvp_ero_ipv4_subobj rro[MAX_RRO_HOPS];
    uint8_t rro_count = 0;
    if (psb->rro_count > 0) {
        memcpy(rro, psb->rro,
               psb->rro_count * sizeof(struct rsvp_ero_ipv4_subobj));
        rro_count = psb->rro_count;
    }
    if (rro_count < MAX_RRO_HOPS) {
        rro[rro_count].type       = RSVP_ERO_IPV4;
        rro[rro_count].length     = sizeof(struct rsvp_ero_ipv4_subobj);
        rro[rro_count].addr       = local_addr;
        rro[rro_count].prefix_len = 32;
        rro[rro_count].res        = 0;
        rro_count++;
        rsvp_builder_add_rro(&b, rro, rro_count);
    }

    size_t len = rsvp_builder_finalize(&b);
    LOG_INFO("  - Sending PATH downstream: LocalSrc %s → IPDest %s, "
             "TunnelDest %s, Len %zu",
             local_str, nh_str, dest_str, len);
    rsvp_send_packet(&local_addr, &ip_dest, buf, len, true);
}

/* ---- PATH message handler ----------------------------------------------- */

static void handle_path_message(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN],
         hop_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->key.sender.source_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET,
              info->hop_v4 ? &info->hop_v4->neighbor_addr : &info->src_ip,
              hop_str, sizeof(hop_str));

    LOG_INFO("Handling PATH: [TunnelID: %d, Dest: %s, Src: %s, PrevHop: %s]",
             ntohs(info->key.session.tunnel_id), dest_str, src_str, hop_str);

    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    uint8_t  err_code = 0;
    uint16_t err_val  = 0;

    if (rsvp_validate_path_message(info, psb, &err_code, &err_val) != RSVP_SUCCESS) {
        LOG_WARN("  - PATH validation failed [TunnelID: %d] — sending PathErr",
                 ntohs(info->key.session.tunnel_id));
        send_path_err(info, err_code, err_val);
        return;
    }

    bool is_new = (psb == NULL);
    if (is_new) {
        LOG_INFO("  - New PATH: creating PSB [TunnelID: %d]",
                 ntohs(info->key.session.tunnel_id));
        psb = rsvp_psb_create(&info->key);
        if (!psb) {
            LOG_ERROR("  - Failed to allocate PSB — dropping PATH");
            return;
        }
        psb->refresh_ms = RSVP_REFRESH_MS;
    } else {
        char old_hop[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &psb->prev_hop.neighbor_addr, old_hop, sizeof(old_hop));
        if (info->hop_v4 &&
            memcmp(&psb->prev_hop.neighbor_addr,
                   &info->hop_v4->neighbor_addr,
                   sizeof(struct in_addr)) != 0) {
            LOG_INFO("  - PHOP changed: %s → %s [TunnelID: %d]",
                     old_hop, hop_str, ntohs(info->key.session.tunnel_id));
        } else {
            LOG_DEBUG("  - Refresh for existing PSB [TunnelID: %d]",
                      ntohs(info->key.session.tunnel_id));
        }
    }

    /* Update state from received objects. */
    if (info->time_values) {
        psb->refresh_ms = ntohl(info->time_values->refresh_ms);
        LOG_DEBUG("  - Refresh interval updated: %u ms", psb->refresh_ms);
    }

    if (info->common_hdr) {
        psb->ttl = info->common_hdr->ttl;
    }

    psb->refresh_count = 0;

    if (info->ero && info->ero_len > 0) {
        const uint8_t* ptr = (const uint8_t*)info->ero;
        size_t rem  = info->ero_len;
        uint8_t cnt = 0;
        while (rem >= 2 && cnt < MAX_ERO_HOPS) {
            const struct rsvp_ero_ipv4_subobj* sub =
                (const struct rsvp_ero_ipv4_subobj*)ptr;
            if (sub->length < 2 || sub->length > rem) break;
            if ((sub->type & 0x7F) == RSVP_ERO_IPV4 &&
                sub->length == sizeof(struct rsvp_ero_ipv4_subobj)) {
                memcpy(&psb->ero[cnt++], ptr, sizeof(struct rsvp_ero_ipv4_subobj));
            } else {
                LOG_DEBUG("  - ERO: Skipping unsupported subobject type %d",
                          sub->type & 0x7F);
            }
            ptr += sub->length;
            rem -= sub->length;
        }
        psb->ero_count = cnt;
        LOG_DEBUG("  - ERO updated: %u hops stored", psb->ero_count);
    }

    if (info->rro && info->rro_len > 0) {
        const uint8_t* ptr = (const uint8_t*)info->rro;
        size_t rem  = info->rro_len;
        uint8_t cnt = 0;
        while (rem >= 2 && cnt < MAX_RRO_HOPS) {
            const struct rsvp_ero_ipv4_subobj* sub =
                (const struct rsvp_ero_ipv4_subobj*)ptr;
            if (sub->length < 2 || sub->length > rem) break;
            if ((sub->type & 0x7F) == RSVP_ERO_IPV4 &&
                sub->length == sizeof(struct rsvp_ero_ipv4_subobj)) {
                memcpy(&psb->rro[cnt++], ptr, sizeof(struct rsvp_ero_ipv4_subobj));
            }
            ptr += sub->length;
            rem -= sub->length;
        }
        psb->rro_count = cnt;
        LOG_DEBUG("  - RRO updated: %u hops recorded", psb->rro_count);
    }

    if (info->tspec) {
        tspec_copy_and_ntoh(&psb->tspec, info->tspec);
        LOG_DEBUG("  - TSpec updated: rate=%.2f bps, size=%.2f bytes",
                  psb->tspec.token_bucket_rate, psb->tspec.token_bucket_size);
    }

    if (info->sess_attr) {
        psb->setup_prio   = info->sess_attr->setup_prio;
        psb->holding_prio = info->sess_attr->holding_prio;
        LOG_DEBUG("  - Session attributes: SetupPrio %u, HoldPrio %u, Flags 0x%02x",
                  psb->setup_prio, psb->holding_prio, info->sess_attr->flags);
    }

    if (info->fast_reroute && !psb->is_bypass_tunnel) {
        /* Transit node honours the FRR request from the ingress. */
        if (info->fast_reroute->flags & RSVP_FRR_FLAG_FACILITY) {
            psb->frr_mode      = RSVP_FRR_FACILITY;
            psb->frr_bandwidth = (uint32_t)rsvp_net_to_float(info->fast_reroute->bandwidth);
            LOG_DEBUG("  - FRR: Facility-backup requested, bandwidth %u bps",
                      psb->frr_bandwidth);
        } else if (info->fast_reroute->flags & RSVP_FRR_FLAG_ONE_TO_ONE) {
            psb->frr_mode = RSVP_FRR_ONE_TO_ONE;
            LOG_DEBUG("  - FRR: One-to-one backup requested");
        }
    }

    if (info->lsp_name[0] != '\0') {
        if (psb->lsp_name) free(psb->lsp_name);
        psb->lsp_name = strdup(info->lsp_name);
        if (psb->lsp_name) {
            LOG_DEBUG("  - LSP name: '%s'", psb->lsp_name);
        } else {
            LOG_ERROR("  - strdup failed for LSP name (OOM) — name not stored");
        }
    }

    /* Store PHOP now that we have validated info->hop_v4 is present. */
    psb->prev_hop    = *info->hop_v4;
    psb->ifindex_in  = ntohl(info->hop_v4->logical_interface);

    /* (Re)start the cleanup timer using the correct RFC 2205 lifetime. */
    uint32_t cleanup_ms = RSVP_CLEANUP_MS(psb->refresh_ms);
    LOG_DEBUG("  - (Re)starting cleanup timer: %u ms", cleanup_ms);
    if (!psb->cleanup_timer.active ||
        !rsvp_timer_reset(&psb->cleanup_timer, cleanup_ms)) {
        rsvp_timer_start(&psb->cleanup_timer, RSVP_TIMER_CLEANUP,
                         cleanup_ms, psb_cleanup_timer_cb, psb);
    }

    /* Start the refresh timer only if not already running. */
    if (!psb->refresh_timer.active) {
        uint32_t next_refresh = get_jittered_refresh(psb->refresh_ms,
                                                      !psb->is_ingress);
        LOG_DEBUG("  - Starting refresh timer: %u ms", next_refresh);
        rsvp_timer_start(&psb->refresh_timer, RSVP_TIMER_REFRESH,
                         next_refresh, psb_refresh_timer_cb, psb);
    }

    struct in_addr dest = info->key.session.dest_addr;

    if (hal_netlink_is_local_addr(&dest)) {
        /* ----------------------------------------------------------------
         * EGRESS role: we are the tunnel endpoint.
         * Trigger a RESV if no reservation exists yet.
         * ---------------------------------------------------------------- */
        LOG_INFO("  - Role: EGRESS (Dest %s is local) [TunnelID: %d]",
                 dest_str, ntohs(info->key.session.tunnel_id));

        struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
        if (!rsb) {
            LOG_INFO("  - Egress: No RSB yet — creating RSB and triggering initial RESV");
            rsb = rsvp_rsb_create(&info->key);
            if (rsb) {
                rsb->associated_psb = psb;
                psb->associated_rsb = rsb;
                rsb->refresh_ms     = psb->refresh_ms;

                uint32_t resv_refresh = get_jittered_refresh(rsb->refresh_ms, false);
                rsvp_timer_start(&rsb->refresh_timer, RSVP_TIMER_REFRESH,
                                 resv_refresh, rsb_refresh_timer_cb, rsb);
                LOG_DEBUG("  - Egress RSB refresh timer: %u ms", resv_refresh);
                send_resv_upstream(rsb);
            } else {
                LOG_ERROR("  - Egress: Failed to allocate RSB — RESV not sent");
            }
        } else {
            LOG_DEBUG("  - Egress: Existing RSB refreshed [TunnelID: %d]",
                      ntohs(info->key.session.tunnel_id));
            rsb->refresh_ms = psb->refresh_ms;
        }

    } else {
        /* ----------------------------------------------------------------
         * TRANSIT (or ingress PATH looping back): forward PATH downstream.
         * ---------------------------------------------------------------- */
        struct in_addr sender_addr = info->key.sender.source_addr;
        if (hal_netlink_is_local_addr(&sender_addr)) {
            LOG_WARN("  - Received own PATH back (Src %s is local) — "
                     "dropping to prevent loop [TunnelID: %d]",
                     src_str, ntohs(info->key.session.tunnel_id));
            return;
        }

        int next_ifindex = -1;
        struct in_addr ip_next = resolve_path_next_hop(psb, &next_ifindex);
        if (next_ifindex < 0) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_next, ip_str, sizeof(ip_str));
            LOG_ERROR("  - TRANSIT: No route to next hop %s — "
                      "sending PathErr [TunnelID: %d]",
                      ip_str, ntohs(info->key.session.tunnel_id));
            send_path_err(info, RSVP_PROTO_ERR_ROUTING_PROBLEM, 0);
            if (is_new) rsvp_psb_delete(psb);
            return;
        }

        char next_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_next, next_str, sizeof(next_str));
        LOG_INFO("  - Role: TRANSIT — forwarding PATH to %s, IfIndex %d "
                 "[TunnelID: %d]",
                 next_str, next_ifindex, ntohs(info->key.session.tunnel_id));
        send_path_downstream(psb);
    }
}

/* ---- RESV message handler ----------------------------------------------- */

static void handle_resv_message(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN],
         nh_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->key.sender.source_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET,
              info->hop_v4 ? &info->hop_v4->neighbor_addr : &info->src_ip,
              nh_str, sizeof(nh_str));

    struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
    uint8_t  err_code = 0;
    uint16_t err_val  = 0;

    if (rsvp_validate_resv_message(info, rsb, &err_code, &err_val) != RSVP_SUCCESS) {
        LOG_WARN("  - RESV validation failed [TunnelID: %d] — sending ResvErr",
                 ntohs(info->key.session.tunnel_id));
        send_resv_err(info, err_code, err_val);
        return;
    }

    uint32_t label = ntohl(info->label->label);
    LOG_INFO("Handling RESV: [TunnelID: %d, Dest: %s, Src: %s, "
             "Label: %u, NextHop: %s]",
             ntohs(info->key.session.tunnel_id), dest_str, src_str,
             label, nh_str);

    bool is_new = (rsb == NULL);
    if (is_new) {
        LOG_INFO("  - New RESV: creating RSB [TunnelID: %d]",
                 ntohs(info->key.session.tunnel_id));
        rsb = rsvp_rsb_create(&info->key);
        if (!rsb) {
            LOG_ERROR("  - Failed to allocate RSB — dropping RESV");
            return;
        }
        rsb->refresh_ms = RSVP_REFRESH_MS;

        struct rsvp_psb* psb = rsvp_psb_find(&info->key);
        if (psb) {
            rsb->associated_psb = psb;
            psb->associated_rsb = rsb;
            rsb->refresh_ms     = psb->refresh_ms;
            LOG_DEBUG("  - New RSB associated with existing PSB [TunnelID: %d]",
                      ntohs(info->key.session.tunnel_id));
        }
    }

    if (info->time_values) {
        rsb->refresh_ms = ntohl(info->time_values->refresh_ms);
    }

    if (info->flowspec) {
        tspec_copy_and_ntoh(&rsb->flowspec, info->flowspec);
        LOG_DEBUG("  - Flowspec updated: rate=%.2f bps [TunnelID: %d]",
                  rsb->flowspec.token_bucket_rate,
                  ntohs(info->key.session.tunnel_id));
    }

    if (info->style) {
        rsb->style = ntohl(info->style->style) & 0xFF;
    }

    /* RFC 2209: Check for blockade before programming hardware.
     * If this is a new RSB that is immediately blockaded, free it to avoid
     * a permanent RSB leak. */
    if (rsvp_is_blockaded(rsb)) {
        LOG_INFO("  - RESV is blockaded — not installing in hardware "
                 "[TunnelID: %d]",
                 ntohs(info->key.session.tunnel_id));
        if (is_new) {
            /* Newly created RSB that is already blockaded: release it cleanly. */
            if (rsb->associated_psb) rsb->associated_psb->associated_rsb = NULL;
            rsvp_rsb_delete(rsb);
        }
        return;
    }

    if (info->common_hdr) rsb->ttl = info->common_hdr->ttl;

    /* (Re)start the cleanup timer. */
    uint32_t cleanup_ms = RSVP_CLEANUP_MS(rsb->refresh_ms);
    LOG_DEBUG("  - (Re)starting RSB cleanup timer: %u ms [TunnelID: %d]",
              cleanup_ms, ntohs(info->key.session.tunnel_id));
    if (!rsb->cleanup_timer.active ||
        !rsvp_timer_reset(&rsb->cleanup_timer, cleanup_ms)) {
        rsvp_timer_start(&rsb->cleanup_timer, RSVP_TIMER_CLEANUP,
                         cleanup_ms, rsb_cleanup_timer_cb, rsb);
    }

    rsb->refresh_count = 0;

    /* RSB refresh timer: only for transit/egress nodes that need to propagate upstream. */
    bool is_ingress = (rsb->associated_psb && rsb->associated_psb->is_ingress);
    if (!is_ingress) {
        if (!rsb->refresh_timer.active) {
            uint32_t next_refresh = get_jittered_refresh(rsb->refresh_ms, true);
            LOG_DEBUG("  - Starting RSB upstream refresh timer: %u ms", next_refresh);
            rsvp_timer_start(&rsb->refresh_timer, RSVP_TIMER_REFRESH,
                             next_refresh, rsb_refresh_timer_cb, rsb);
        }
    } else if (rsb->refresh_timer.active) {
        LOG_DEBUG("  - Stopping RSB refresh timer (role is ingress) "
                  "[TunnelID: %d]",
                  ntohs(info->key.session.tunnel_id));
        rsvp_timer_stop(&rsb->refresh_timer);
    }

    uint32_t        old_label_out = rsb->label_out;
    struct in_addr  old_next_hop  = rsb->next_hop.neighbor_addr;

    if (info->label)  rsb->label_out = label;
    if (info->hop_v4) rsb->next_hop  = *info->hop_v4;

    bool label_changed = (rsb->label_out != old_label_out);
    bool hop_changed   = (memcmp(&rsb->next_hop.neighbor_addr,
                                  &old_next_hop,
                                  sizeof(struct in_addr)) != 0);

    if (is_new || label_changed || hop_changed) {
        if (label_changed) {
            LOG_INFO("  - Label changed: %u → %u [TunnelID: %d]",
                     old_label_out, rsb->label_out,
                     ntohs(info->key.session.tunnel_id));
        }
        if (hop_changed) {
            char old_str[INET_ADDRSTRLEN], new_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &old_next_hop,              old_str, sizeof(old_str));
            inet_ntop(AF_INET, &rsb->next_hop.neighbor_addr, new_str, sizeof(new_str));
            LOG_INFO("  - NextHop changed: %s → %s [TunnelID: %d]",
                     old_str, new_str, ntohs(info->key.session.tunnel_id));
        }

        if (!rsb->associated_psb) {
            LOG_WARN("  - No associated PSB — cannot program MPLS forwarding "
                     "[TunnelID: %d]",
                     ntohs(info->key.session.tunnel_id));
        } else {
            struct rsvp_psb* psb = rsb->associated_psb;
            struct in_addr dest_tmp   = psb->key.session.dest_addr;
            struct in_addr next_hop_a = rsb->next_hop.neighbor_addr;

            bool is_transit = (psb->prev_hop.neighbor_addr.s_addr != 0);
            if (is_transit) {
                /* Transit node: SWAP label_in → label_out. */
                if (rsb->label_in == 0) {
                    rsb->label_in = label_mgr_alloc();
                    if (rsb->label_in == 0) {
                        LOG_ERROR("  - TRANSIT: Label allocation FAILED — "
                                  "sending ResvErr [TunnelID: %d]",
                                  ntohs(info->key.session.tunnel_id));
                        if (is_new) rsvp_rsb_cleanup(rsb, false);
                        send_resv_err(info, RSVP_PROTO_ERR_ADMISSION_CONTROL, 0);
                        return;
                    }
                    LOG_DEBUG("  - Allocated inbound label: %u [TunnelID: %d]",
                              rsb->label_in, ntohs(info->key.session.tunnel_id));
                }
                LOG_INFO("  - TRANSIT: Programming MPLS SWAP "
                         "[in=%u → out=%u, nexthop=%s, if=%u, dest=%s]",
                         rsb->label_in, rsb->label_out,
                         inet_ntoa(next_hop_a),
                         ntohl(rsb->next_hop.logical_interface),
                         inet_ntoa(dest_tmp));
                hal_mpls_install(rsb->label_in, rsb->label_out,
                                 ntohl(rsb->next_hop.logical_interface),
                                 &next_hop_a, &dest_tmp);

                char prev_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &psb->prev_hop.neighbor_addr,
                          prev_str, sizeof(prev_str));
                LOG_INFO("  - TRANSIT: Forwarding RESV upstream to %s "
                         "[TunnelID: %d]",
                         prev_str, ntohs(info->key.session.tunnel_id));
                send_resv_upstream(rsb);
            } else {
                /* Ingress node: PUSH label onto unlabelled traffic. */
                LOG_INFO("  - INGRESS: Programming MPLS PUSH "
                         "[label=%u, nexthop=%s, if=%u, dest=%s]",
                         rsb->label_out,
                         inet_ntoa(next_hop_a),
                         ntohl(rsb->next_hop.logical_interface),
                         inet_ntoa(dest_tmp));
                hal_mpls_install(0, rsb->label_out,
                                 ntohl(rsb->next_hop.logical_interface),
                                 &next_hop_a, &dest_tmp);
                LOG_INFO("  - INGRESS: LSP reservation COMPLETE "
                         "[TunnelID: %d]",
                         ntohs(rsb->key.session.tunnel_id));
            }
        }
    } else {
        /* Soft-state refresh with no change. */
        LOG_DEBUG("  - RESV soft-state refresh (no label/hop change) "
                  "[TunnelID: %d]",
                  ntohs(info->key.session.tunnel_id));
        if (rsb->associated_psb &&
            rsb->associated_psb->prev_hop.neighbor_addr.s_addr != 0 &&
            !rsb->associated_psb->is_ingress) {
            char prev_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET,
                      &rsb->associated_psb->prev_hop.neighbor_addr,
                      prev_str, sizeof(prev_str));
            LOG_DEBUG("  - Propagating RESV refresh upstream to %s", prev_str);
            send_resv_upstream(rsb);
        }
    }
}

/* ---- PathTear handler --------------------------------------------------- */

static void handle_path_tear(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->src_ip,               src_str,  sizeof(src_str));

    LOG_INFO("Handling PathTear from %s: [TunnelID: %d, Dest: %s, Src: %s]",
             src_str, ntohs(info->key.session.tunnel_id), dest_str,
             inet_ntoa(info->key.sender.source_addr));

    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    if (psb) {
        /* propagate=true: forward PathTear downstream before cleaning up. */
        rsvp_psb_cleanup(psb, true);
    } else {
        LOG_WARN("  - No matching PSB for PathTear (from %s) — ignoring",
                 src_str);
    }

    /* RFC 2209: PathTear removes associated blockade state. */
    struct rsvp_bsb* bsb = rsvp_bsb_find(&info->key);
    if (bsb) {
        LOG_INFO("  - Removing BSB matching PathTear [TunnelID: %d]",
                 ntohs(info->key.session.tunnel_id));
        rsvp_timer_stop(&bsb->blockade_timer);
        rsvp_bsb_delete(bsb);
    }
}

/* ---- ResvTear handler --------------------------------------------------- */

static void handle_resv_tear(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->src_ip,               src_str,  sizeof(src_str));

    LOG_INFO("Handling ResvTear from %s: [TunnelID: %d, Dest: %s, Src: %s]",
             src_str, ntohs(info->key.session.tunnel_id), dest_str,
             inet_ntoa(info->key.sender.source_addr));

    struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
    if (rsb) {
        rsvp_rsb_cleanup(rsb, true);
    } else {
        LOG_WARN("  - No matching RSB for ResvTear (from %s) — ignoring",
                 src_str);
    }

    struct rsvp_bsb* bsb = rsvp_bsb_find(&info->key);
    if (bsb) {
        LOG_INFO("  - Removing BSB matching ResvTear [TunnelID: %d]",
                 ntohs(info->key.session.tunnel_id));
        rsvp_timer_stop(&bsb->blockade_timer);
        rsvp_bsb_delete(bsb);
    }
}

/* ---- PathErr handler ---------------------------------------------------- */

static void handle_path_err(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN],
         node_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->src_ip,               src_str,  sizeof(src_str));

    if (info->error_spec) {
        inet_ntop(AF_INET, &info->error_spec->error_node, node_str, sizeof(node_str));
        LOG_INFO("Handling PathErr from %s: [TunnelID: %d, Dest: %s] "
                 "Code: %d, Value: %d, ErrorNode: %s",
                 src_str, ntohs(info->key.session.tunnel_id), dest_str,
                 info->error_spec->error_code,
                 ntohs(info->error_spec->error_value),
                 node_str);
    } else {
        LOG_WARN("Handling PathErr from %s: [TunnelID: %d, Dest: %s] "
                 "MISSING ERROR_SPEC",
                 src_str, ntohs(info->key.session.tunnel_id), dest_str);
    }

    struct rsvp_psb* psb = rsvp_psb_find(&info->key);
    if (!psb) {
        LOG_INFO("  - No PSB found for PathErr — error processing complete");
        return;
    }

    /* If this node is the ingress (head-end) the error terminates here. */
    if (psb->is_ingress || psb->prev_hop.neighbor_addr.s_addr == 0) {
        LOG_INFO("  - PathErr reached head-end (Ingress) "
                 "[TunnelID: %d] — error processing complete",
                 ntohs(info->key.session.tunnel_id));
        return;
    }

    /* Rebuild PathErr and propagate upstream. */
    struct in_addr prev_addr = psb->prev_hop.neighbor_addr;
    char prev_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &prev_addr, prev_str, sizeof(prev_str));
    LOG_INFO("  - Propagating PathErr upstream to %s [TunnelID: %d]",
             prev_str, ntohs(info->key.session.tunnel_id));

    struct in_addr local_addr = {0};
    struct in_addr dummy      = {0};
    int out_idx = hal_netlink_get_egress_if(&prev_addr, &dummy);
    if (out_idx >= 0) {
        hal_netlink_get_local_addr(out_idx, &local_addr);
    } else {
        local_addr = psb->key.session.dest_addr;
    }

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATHERR);
    b.hdr->ttl = 255;

    struct in_addr dest_c    = psb->key.session.dest_addr;
    struct in_addr ext_dest  = psb->key.session.extended_tunnel_id;
    rsvp_builder_add_session_ipv4(&b, &dest_c,
                                   ntohs(psb->key.session.tunnel_id),
                                   &ext_dest);
    rsvp_builder_add_hop_ipv4(&b, &local_addr,
                               out_idx >= 0 ? (uint32_t)out_idx
                                            : psb->ifindex_in);
    if (info->error_spec) {
        rsvp_builder_add_obj(&b, RSVP_CLASS_ERROR_SPEC, 1,
                             info->error_spec, sizeof(*info->error_spec));
    }
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7,
                         &psb->key.sender, sizeof(psb->key.sender));

    size_t len = rsvp_builder_finalize(&b);
    if (rsvp_send_packet(&local_addr, &prev_addr, buf, len, false) < 0) {
        LOG_ERROR("  - Failed to send PathErr upstream to %s", prev_str);
    }
}

/* ---- BSB cleanup callback ----------------------------------------------- */

static void bsb_cleanup_timer_cb(void* arg) {
    struct rsvp_bsb* bsb = (struct rsvp_bsb*)arg;
    LOG_INFO("BSB Blockade Timer Expired [TunnelID: %d] — removing blockade",
             ntohs(bsb->key.session.tunnel_id));
    rsvp_bsb_delete(bsb);
}

/* ---- ResvErr handler ---------------------------------------------------- */

static void handle_resv_err(struct rsvp_message_info* info) {
    char dest_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN],
         node_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->key.session.dest_addr, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, &info->src_ip,               src_str,  sizeof(src_str));

    if (info->error_spec) {
        inet_ntop(AF_INET, &info->error_spec->error_node, node_str, sizeof(node_str));
        LOG_INFO("Handling ResvErr from %s: [TunnelID: %d, Dest: %s] "
                 "Code: %d, Value: %d, ErrorNode: %s",
                 src_str, ntohs(info->key.session.tunnel_id), dest_str,
                 info->error_spec->error_code,
                 ntohs(info->error_spec->error_value),
                 node_str);

        /* RFC 2209: An Admission Control failure carrying a Flowspec triggers
         * blockade state creation/update. */
        if (info->error_spec->error_code == RSVP_PROTO_ERR_ADMISSION_CONTROL &&
            info->flowspec) {
            struct rsvp_bsb* bsb = rsvp_bsb_find(&info->key);
            if (!bsb) bsb = rsvp_bsb_create(&info->key);
            if (bsb) {
                tspec_copy_and_ntoh(&bsb->flowspec_qb, info->flowspec);
                uint32_t tb_ms = RSVP_CLEANUP_MS(RSVP_REFRESH_MS);
                LOG_INFO("  - BSB created/updated [TunnelID: %d]: "
                         "Qb rate=%.2f bps, timer=%u ms",
                         ntohs(info->key.session.tunnel_id),
                         bsb->flowspec_qb.token_bucket_rate, tb_ms);
                if (bsb->blockade_timer.active) {
                    rsvp_timer_reset(&bsb->blockade_timer, tb_ms);
                } else {
                    rsvp_timer_start(&bsb->blockade_timer,
                                     RSVP_TIMER_CLEANUP, tb_ms,
                                     bsb_cleanup_timer_cb, bsb);
                }
            }
        }
    } else {
        LOG_WARN("Handling ResvErr from %s: [TunnelID: %d] MISSING ERROR_SPEC",
                 src_str, ntohs(info->key.session.tunnel_id));
    }

    struct rsvp_rsb* rsb = rsvp_rsb_find(&info->key);
    if (!rsb) {
        LOG_WARN("  - No matching RSB for ResvErr (from %s) — ignoring",
                 src_str);
        return;
    }

    struct in_addr dest_chk = info->key.session.dest_addr;
    if (hal_netlink_is_local_addr(&dest_chk)) {
        LOG_INFO("  - ResvErr reached tail-end (Egress) "
                 "[TunnelID: %d] — error processing complete",
                 ntohs(info->key.session.tunnel_id));
        return;
    }

    LOG_INFO("  - Propagating ResvErr downstream [TunnelID: %d]",
             ntohs(info->key.session.tunnel_id));
    propagate_resv_err(rsb, info->error_spec);
}

/* ---- ResvConf and SRefresh handlers ------------------------------------- */

static void handle_resv_conf(struct rsvp_message_info* info) {
    LOG_INFO("Handling ResvConf [TunnelID: %d] — reservation confirmed by receiver",
             ntohs(info->key.session.tunnel_id));
    /* RFC 2205 §3.14: Forward ResvConf toward the receiver (downstream). */
}

static void handle_srefresh(struct rsvp_message_info* info) {
    (void)info;
    LOG_INFO("Handling SRefresh (Summary Refresh, RFC 2961)");
    /* RFC 2961: Refresh active states referenced in the MESSAGE_ID_LIST
     * without resending full Path/Resv messages.  Full implementation TBD. */
}

/* ---- Main dispatch ------------------------------------------------------- */

void rsvp_handle_message(struct rsvp_message_info* info) {
    switch (info->common_hdr->msg_type) {
        case RSVP_MSG_PATH:     handle_path_message(info); break;
        case RSVP_MSG_RESV:     handle_resv_message(info); break;
        case RSVP_MSG_PATHTEAR: handle_path_tear(info);    break;
        case RSVP_MSG_RESVTEAR: handle_resv_tear(info);    break;
        case RSVP_MSG_PATHERR:  handle_path_err(info);     break;
        case RSVP_MSG_RESVERR:  handle_resv_err(info);     break;
        case RSVP_MSG_RESVCONF: handle_resv_conf(info);    break;
        case RSVP_MSG_SREFRESH: handle_srefresh(info);     break;
        default:
            LOG_WARN("Unsupported RSVP message type %d — discarding",
                     info->common_hdr->msg_type);
            break;
    }
}

/* ---- RESV upstream sender ----------------------------------------------- */

static void send_resv_upstream(struct rsvp_rsb* rsb) {
    struct rsvp_psb* psb = rsb->associated_psb;
    if (!psb) {
        LOG_ERROR("send_resv_upstream: RSB [TunnelID: %d] has no associated PSB",
                  ntohs(rsb->key.session.tunnel_id));
        return;
    }

    /* Allocate an inbound label for this node if not yet done.
     * Egress nodes get a label here (PHP or explicit-null could be applied
     * but we use a real label for simplicity). */
    if (rsb->label_in == 0) {
        rsb->label_in = label_mgr_alloc();
        if (rsb->label_in == 0) {
            LOG_ERROR("send_resv_upstream: Label allocation FAILED "
                      "[TunnelID: %d]",
                      ntohs(rsb->key.session.tunnel_id));
            return;
        }
        LOG_DEBUG("  - Allocated inbound label: %u [TunnelID: %d]",
                  rsb->label_in, ntohs(rsb->key.session.tunnel_id));
    }

    struct in_addr dest     = psb->key.session.dest_addr;
    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;
    struct in_addr nbr      = psb->prev_hop.neighbor_addr;

    /* Resolve the interface toward PHOP to get the correct local source address. */
    struct in_addr local_addr = {0};
    struct in_addr dummy_gw   = {0};
    int out_idx = hal_netlink_get_egress_if(&nbr, &dummy_gw);
    if (out_idx >= 0) {
        hal_netlink_get_local_addr(out_idx, &local_addr);
    }

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESV);
    b.hdr->ttl = (rsb->ttl > 0) ? rsb->ttl - 1 : 255;

    /* RFC 2205 RESV message order:
     *   SESSION, RSVP_HOP, TIME_VALUES, [RESV_CONFIRM], STYLE,
     *   <flow descriptor list>: [FLOWSPEC] [FILTER_SPEC] [LABEL]
     */
    rsvp_builder_add_session_ipv4(&b, &dest,
                                   ntohs(psb->key.session.tunnel_id),
                                   &ext_dest);
    rsvp_builder_add_hop_ipv4(&b, &local_addr,
                               out_idx >= 0 ? (uint32_t)out_idx
                                            : psb->ifindex_in);
    rsvp_builder_add_time_values(&b, rsb->refresh_ms);
    rsvp_builder_add_style(&b, rsb->style ? rsb->style : RSVP_STYLE_FF);

    struct rsvp_sender_tspec merged;
    rsvp_compute_merged_flowspec(psb, &merged);
    rsvp_builder_add_flowspec(&b, &merged);

    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7,
                         &psb->key.sender, sizeof(psb->key.sender));
    rsvp_builder_add_label_ipv4(&b, rsb->label_in);

    size_t len = rsvp_builder_finalize(&b);

    char nbr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &nbr, nbr_str, sizeof(nbr_str));
    LOG_INFO("  - Sending RESV upstream to %s "
             "[TunnelID: %d, Label: %u, Len: %zu]",
             nbr_str, ntohs(rsb->key.session.tunnel_id), rsb->label_in, len);
    rsvp_send_packet(&local_addr, &nbr, buf, len, false);
}

/* ---- PathTear propagation ----------------------------------------------- */

/* Forward a PathTear downstream toward the tunnel endpoint.
 *
 * RFC 3209: PathTear must be addressed to the same next hop that PATH
 * messages use — i.e. the ERO-directed next hop, not just the tunnel
 * destination.  This ensures each transit node processes the tear.
 */
static void propagate_path_tear(struct rsvp_psb* psb) {
    int ifindex = -1;
    struct in_addr ip_dest = resolve_path_next_hop(psb, &ifindex);

    char dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_dest, dest_str, sizeof(dest_str));

    if (ifindex < 0) {
        LOG_WARN("propagate_path_tear: No route to next hop %s "
                 "[TunnelID: %d] — cannot propagate",
                 dest_str, ntohs(psb->key.session.tunnel_id));
        return;
    }

    struct in_addr local_addr = {0};
    if (hal_netlink_get_local_addr(ifindex, &local_addr) < 0) {
        local_addr = psb->key.sender.source_addr;
    }

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_PATHTEAR);
    b.hdr->ttl = (psb->ttl > 0) ? psb->ttl - 1 : 255;

    struct in_addr tun_dest = psb->key.session.dest_addr;
    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;
    rsvp_builder_add_session_ipv4(&b, &tun_dest,
                                   ntohs(psb->key.session.tunnel_id),
                                   &ext_dest);
    rsvp_builder_add_hop_ipv4(&b, &local_addr, (uint32_t)ifindex);

    /* RFC 2205 §3.8: PathTear = SESSION, RSVP_HOP, SENDER_TEMPLATE */
    rsvp_builder_add_obj(&b, RSVP_CLASS_SENDER_TEMPLATE, 7,
                         &psb->key.sender, sizeof(psb->key.sender));

    size_t len = rsvp_builder_finalize(&b);
    LOG_INFO("  - Sending PathTear downstream to %s "
             "[TunnelID: %d, Len: %zu]",
             dest_str, ntohs(psb->key.session.tunnel_id), len);
    if (rsvp_send_packet(&local_addr, &ip_dest, buf, len, true) < 0) {
        LOG_ERROR("  - Failed to send PathTear to %s", dest_str);
    }
}

/* ---- ResvTear propagation ----------------------------------------------- */

/* RFC 2205 §3.8 ResvTear message format:
 *   SESSION, RSVP_HOP, [SCOPE], STYLE, <flow descriptor list>
 *
 * TIME_VALUES is NOT part of the ResvTear format and must not be included.
 */
static void propagate_resv_tear(struct rsvp_rsb* rsb) {
    if (!rsb->associated_psb) {
        LOG_ERROR("propagate_resv_tear: No associated PSB "
                  "[TunnelID: %d]",
                  ntohs(rsb->key.session.tunnel_id));
        return;
    }

    struct rsvp_psb* psb  = rsb->associated_psb;
    struct in_addr prev   = psb->prev_hop.neighbor_addr;

    if (prev.s_addr == 0) {
        LOG_DEBUG("propagate_resv_tear: Reached ingress (no upstream PHOP) "
                  "[TunnelID: %d]",
                  ntohs(rsb->key.session.tunnel_id));
        return;
    }

    char prev_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &prev, prev_str, sizeof(prev_str));

    struct in_addr local_addr = {0};
    struct in_addr dummy      = {0};
    int ifindex = hal_netlink_get_egress_if(&prev, &dummy);
    if (ifindex >= 0) {
        hal_netlink_get_local_addr(ifindex, &local_addr);
    }

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESVTEAR);

    struct in_addr dest     = psb->key.session.dest_addr;
    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;
    rsvp_builder_add_session_ipv4(&b, &dest,
                                   ntohs(psb->key.session.tunnel_id),
                                   &ext_dest);
    rsvp_builder_add_hop_ipv4(&b, &local_addr,
                               ifindex >= 0 ? (uint32_t)ifindex
                                            : ntohl(psb->prev_hop.logical_interface));
    rsvp_builder_add_style(&b, rsb->style ? rsb->style : RSVP_STYLE_FF);
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7,
                         &psb->key.sender, sizeof(psb->key.sender));

    size_t len = rsvp_builder_finalize(&b);
    LOG_INFO("  - Sending ResvTear upstream to %s "
             "[TunnelID: %d, Len: %zu]",
             prev_str, ntohs(rsb->key.session.tunnel_id), len);
    if (rsvp_send_packet(&local_addr, &prev, buf, len, false) < 0) {
        LOG_ERROR("  - Failed to send ResvTear to %s", prev_str);
    }
}

/* ---- ResvErr propagation ------------------------------------------------ */

static void propagate_resv_err(struct rsvp_rsb* rsb,
                                struct rsvp_error_spec_ipv4* err_spec) {
    if (!rsb->associated_psb) {
        LOG_WARN("propagate_resv_err: No associated PSB "
                 "[TunnelID: %d]",
                 ntohs(rsb->key.session.tunnel_id));
        return;
    }

    struct rsvp_psb* psb = rsb->associated_psb;
    struct in_addr dest  = psb->key.session.dest_addr;
    struct in_addr gw    = {0};
    int ifindex = hal_netlink_get_egress_if(&dest, &gw);
    if (ifindex < 0) {
        LOG_WARN("propagate_resv_err: No route to dest %s",
                 inet_ntoa(dest));
        return;
    }

    struct in_addr local_addr = {0};
    hal_netlink_get_local_addr(ifindex, &local_addr);

    uint8_t buf[1024];
    struct rsvp_builder b;
    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_RESVERR);
    b.hdr->ttl = 255;

    struct in_addr ext_dest = psb->key.session.extended_tunnel_id;
    rsvp_builder_add_session_ipv4(&b, &dest,
                                   ntohs(psb->key.session.tunnel_id),
                                   &ext_dest);
    rsvp_builder_add_hop_ipv4(&b, &local_addr, (uint32_t)ifindex);
    if (err_spec) {
        rsvp_builder_add_obj(&b, RSVP_CLASS_ERROR_SPEC, 1,
                             err_spec, sizeof(*err_spec));
    }
    rsvp_builder_add_style(&b, RSVP_STYLE_FF);
    rsvp_builder_add_obj(&b, RSVP_CLASS_FILTER_SPEC, 7,
                         &psb->key.sender, sizeof(psb->key.sender));

    size_t len = rsvp_builder_finalize(&b);
    LOG_INFO("  - Propagating ResvErr downstream to %s "
             "[TunnelID: %d]",
             inet_ntoa(dest), ntohs(rsb->key.session.tunnel_id));
    rsvp_send_packet(&local_addr, &dest, buf, len, false);
}

/* ---- RSB resource cleanup ----------------------------------------------- */

static void rsb_cleanup_resources(struct rsvp_rsb* rsb) {
    if (!rsb) return;

    bool is_ingress = (rsb->associated_psb && rsb->associated_psb->is_ingress);
    struct in_addr* dest_ptr = NULL;
    struct in_addr  dest_tmp = {0};

    if (rsb->associated_psb) {
        dest_tmp = rsb->associated_psb->key.session.dest_addr;
        dest_ptr = &dest_tmp;
    }

    if (rsb->label_in != 0) {
        LOG_DEBUG("  - Removing MPLS entry for inbound label %u "
                  "[TunnelID: %d]",
                  rsb->label_in,
                  ntohs(rsb->key.session.tunnel_id));
        hal_mpls_remove(rsb->label_in, dest_ptr);
        label_mgr_free(rsb->label_in);
        rsb->label_in = 0;
    } else if (is_ingress) {
        LOG_DEBUG("  - Removing ingress MPLS PUSH entry "
                  "[TunnelID: %d]",
                  ntohs(rsb->key.session.tunnel_id));
        hal_mpls_remove(0, dest_ptr);
    }

    rsvp_timer_stop(&rsb->refresh_timer);
    rsvp_timer_stop(&rsb->cleanup_timer);
}

static void rsvp_rsb_cleanup(struct rsvp_rsb* rsb, bool propagate) {
    if (!rsb) return;

    bool is_ingress = (rsb->associated_psb && rsb->associated_psb->is_ingress);
    if (propagate && !is_ingress) {
        propagate_resv_tear(rsb);
    }

    rsb_cleanup_resources(rsb);

    /* Clear the cross-pointer before deleting so the PSB does not hold a
     * dangling reference. */
    if (rsb->associated_psb) {
        rsb->associated_psb->associated_rsb = NULL;
    }

    rsvp_rsb_delete(rsb);
}

static void rsvp_psb_cleanup(struct rsvp_psb* psb, bool propagate) {
    if (!psb) return;

    struct in_addr dest = psb->key.session.dest_addr;
    bool is_egress = hal_netlink_is_local_addr(&dest);

    if (propagate && !is_egress) {
        propagate_path_tear(psb);
    }

    /* Clean up the associated RSB without further propagation — the PathTear
     * above already triggers ResvTear propagation on any downstream nodes. */
    if (psb->associated_rsb) {
        rsvp_rsb_cleanup(psb->associated_rsb, false);
    }

    rsvp_timer_stop(&psb->refresh_timer);
    rsvp_timer_stop(&psb->cleanup_timer);
    rsvp_psb_delete(psb);
}

/* ---- Timer callbacks ----------------------------------------------------- */

static void psb_refresh_timer_cb(void* arg) {
    struct rsvp_psb* psb = (struct rsvp_psb*)arg;
    struct in_addr dest  = psb->key.session.dest_addr;

    LOG_DEBUG("PSB Refresh Timer: [TunnelID: %d]",
              ntohs(psb->key.session.tunnel_id));

    /* Ingress always refreshes. Transit nodes refresh only if the destination
     * is not local (i.e. they are not also the egress). */
    if (psb->is_ingress || !hal_netlink_is_local_addr(&dest)) {
        LOG_INFO("  - Sending PATH refresh downstream [TunnelID: %d]",
                 ntohs(psb->key.session.tunnel_id));
        send_path_downstream(psb);
    }

    bool is_transit = (!psb->is_ingress && psb->prev_hop.neighbor_addr.s_addr != 0);
    uint32_t next = get_jittered_refresh(psb->refresh_ms, is_transit);
    LOG_DEBUG("  - Rescheduling PSB refresh timer: %u ms", next);
    rsvp_timer_start(&psb->refresh_timer, RSVP_TIMER_REFRESH,
                     next, psb_refresh_timer_cb, psb);
}

static void psb_cleanup_timer_cb(void* arg) {
    struct rsvp_psb* psb = (struct rsvp_psb*)arg;
    LOG_WARN("PSB Cleanup Timer Expired [TunnelID: %d] — "
             "no PATH refresh received in time, tearing down state",
             ntohs(psb->key.session.tunnel_id));
    rsvp_psb_cleanup(psb, true);
}

static void rsb_refresh_timer_cb(void* arg) {
    struct rsvp_rsb* rsb = (struct rsvp_rsb*)arg;
    bool is_backup = false;

    LOG_DEBUG("RSB Refresh Timer: [TunnelID: %d]",
              ntohs(rsb->key.session.tunnel_id));

    if (rsb->associated_psb) {
        struct in_addr dest = rsb->associated_psb->key.session.dest_addr;
        is_backup = !hal_netlink_is_local_addr(&dest);
    }

    if (rsb->associated_psb &&
        rsb->associated_psb->prev_hop.neighbor_addr.s_addr != 0 &&
        !rsb->associated_psb->is_ingress) {
        LOG_INFO("  - Sending RESV refresh upstream [TunnelID: %d]",
                 ntohs(rsb->key.session.tunnel_id));
        send_resv_upstream(rsb);
    }

    uint32_t next = get_jittered_refresh(rsb->refresh_ms, is_backup);
    LOG_DEBUG("  - Rescheduling RSB refresh timer: %u ms", next);
    rsvp_timer_start(&rsb->refresh_timer, RSVP_TIMER_REFRESH,
                     next, rsb_refresh_timer_cb, rsb);
}

static void rsb_cleanup_timer_cb(void* arg) {
    struct rsvp_rsb* rsb = (struct rsvp_rsb*)arg;
    LOG_WARN("RSB Cleanup Timer Expired [TunnelID: %d] — "
             "no RESV refresh received in time, tearing down state",
             ntohs(rsb->key.session.tunnel_id));
    rsvp_rsb_cleanup(rsb, true);
}

/* =========================================================================
 * Public API
 * ========================================================================= */

/* ---- rsvp_initiate_path ------------------------------------------------- */

void rsvp_initiate_path(struct in_addr* src, struct in_addr* dest,
                        uint16_t tunnel_id, const char* lsp_name) {
    rsvp_initiate_path_with_ero(src, dest, tunnel_id, lsp_name,
                                 NULL, 0, false);
}

/* ---- rsvp_initiate_path_with_ero ---------------------------------------- */

void rsvp_initiate_path_with_ero(struct in_addr* src, struct in_addr* dest,
                                  uint16_t tunnel_id, const char* lsp_name,
                                  struct rsvp_ero_ipv4_subobj* ero,
                                  uint8_t ero_count,
                                  bool request_frr) {
    char src_str[INET_ADDRSTRLEN], dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, src,  src_str,  sizeof(src_str));
    inet_ntop(AF_INET, dest, dest_str, sizeof(dest_str));

    LOG_INFO("Initiating PATH: [TunnelID: %u, Dest: %s, Src: %s, "
             "LSP: '%s', ERO hops: %u, FRR: %s]",
             tunnel_id, dest_str, src_str,
             lsp_name ? lsp_name : "N/A",
             ero_count,
             request_frr ? "facility-backup" : "none");

    struct rsvp_path_key key;
    memset(&key, 0, sizeof(key));
    key.session.dest_addr          = *dest;
    key.session.tunnel_id          = htons(tunnel_id);
    key.session.extended_tunnel_id = *src; /* RFC 3209: extended tunnel ID = ingress addr */
    key.sender.source_addr         = *src;
    key.sender.lsp_id              = htons(next_lsp_id++);

    struct rsvp_psb* psb = rsvp_psb_find(&key);
    if (!psb) {
        psb = rsvp_psb_create(&key);
        if (!psb) {
            LOG_ERROR("Initiate PATH: Failed to allocate PSB "
                      "[TunnelID: %u]", tunnel_id);
            return;
        }
        psb->refresh_ms = RSVP_REFRESH_MS;
        psb->is_ingress = true;

        if (lsp_name) {
            psb->lsp_name = strdup(lsp_name);
        }

        if (ero && ero_count > 0) {
            uint8_t cnt = (ero_count > MAX_ERO_HOPS) ? MAX_ERO_HOPS : ero_count;
            memcpy(psb->ero, ero, cnt * sizeof(struct rsvp_ero_ipv4_subobj));
            psb->ero_count = cnt;
            LOG_DEBUG("  - Stored %u ERO hops", psb->ero_count);
        }

        if (request_frr) {
            psb->frr_mode      = RSVP_FRR_FACILITY;
            psb->frr_bandwidth = 0; /* Operator can set via rsvp_frr_enable_protection */
            LOG_DEBUG("  - FRR facility-backup requested");
        }

        uint32_t refresh_ms = get_jittered_refresh(psb->refresh_ms, false);
        rsvp_timer_start(&psb->refresh_timer, RSVP_TIMER_REFRESH,
                         refresh_ms, psb_refresh_timer_cb, psb);
        LOG_DEBUG("  - Ingress refresh timer: %u ms", refresh_ms);
    } else {
        LOG_DEBUG("  - PSB already exists for TunnelID %u — "
                  "re-sending PATH", tunnel_id);
    }

    send_path_downstream(psb);
}

/* ---- rsvp_initiate_bypass_tunnel ---------------------------------------- */

void rsvp_initiate_bypass_tunnel(struct in_addr* src, struct in_addr* dest,
                                  uint16_t tunnel_id, const char* name,
                                  struct rsvp_ero_ipv4_subobj* ero,
                                  uint8_t ero_count,
                                  uint32_t protected_ifindex) {
    char src_str[INET_ADDRSTRLEN], dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, src,  src_str,  sizeof(src_str));
    inet_ntop(AF_INET, dest, dest_str, sizeof(dest_str));

    LOG_INFO("Initiating Bypass Tunnel: [TunnelID: %u, Src: %s, Dest: %s, "
             "ProtectedIfIndex: %u, ERO hops: %u, Name: '%s']",
             tunnel_id, src_str, dest_str, protected_ifindex, ero_count,
             name ? name : "N/A");

    /* A bypass tunnel is established using a normal PATH with ERO.
     * The is_bypass_tunnel flag marks it so the state machine handles it
     * correctly (no FAST_REROUTE object, not counted in FRR triggering). */
    struct rsvp_path_key key;
    memset(&key, 0, sizeof(key));
    key.session.dest_addr          = *dest;
    key.session.tunnel_id          = htons(tunnel_id);
    key.session.extended_tunnel_id = *src;
    key.sender.source_addr         = *src;
    key.sender.lsp_id              = htons(next_lsp_id++);

    struct rsvp_psb* psb = rsvp_psb_find(&key);
    if (psb) {
        LOG_DEBUG("  - Bypass tunnel PSB already exists [TunnelID: %u]",
                  tunnel_id);
        return;
    }

    psb = rsvp_psb_create(&key);
    if (!psb) {
        LOG_ERROR("Bypass tunnel: Failed to allocate PSB [TunnelID: %u]",
                  tunnel_id);
        return;
    }

    psb->refresh_ms           = RSVP_REFRESH_MS;
    psb->is_ingress           = true;
    psb->is_bypass_tunnel     = true;
    psb->frr_protected_ifindex = protected_ifindex;

    if (name) psb->lsp_name = strdup(name);

    if (ero && ero_count > 0) {
        uint8_t cnt = (ero_count > MAX_ERO_HOPS) ? MAX_ERO_HOPS : ero_count;
        memcpy(psb->ero, ero, cnt * sizeof(struct rsvp_ero_ipv4_subobj));
        psb->ero_count = cnt;
    }

    uint32_t refresh_ms = get_jittered_refresh(psb->refresh_ms, false);
    rsvp_timer_start(&psb->refresh_timer, RSVP_TIMER_REFRESH,
                     refresh_ms, psb_refresh_timer_cb, psb);

    LOG_DEBUG("  - Bypass tunnel PSB created, sending initial PATH");
    send_path_downstream(psb);
}

/* ---- rsvp_frr_enable_protection ----------------------------------------- */

rsvp_error_t rsvp_frr_enable_protection(uint16_t tunnel_id, uint16_t lsp_id,
                                          rsvp_frr_mode_t frr_mode,
                                          uint16_t bypass_tunnel_id) {
    LOG_INFO("FRR: Enabling protection for LSP [TunnelID: %u, LSPID: %u] → "
             "bypass TunnelID %u, mode %s",
             tunnel_id, lsp_id, bypass_tunnel_id,
             frr_mode == RSVP_FRR_FACILITY ? "facility" : "one-to-one");

    struct rsvp_psb* protected_psb = rsvp_psb_find_by_id(tunnel_id, lsp_id);
    if (!protected_psb) {
        LOG_WARN("FRR: Protected PSB not found [TunnelID: %u, LSPID: %u]",
                 tunnel_id, lsp_id);
        return RSVP_ERR_NOT_FOUND;
    }

    /* Locate the bypass PSB: scan all hash buckets looking for a PSB whose
     * tunnel_id matches and that is marked as a bypass.  O(HASH_SIZE) rather
     * than the O(65535 * HASH_SIZE) ID-exhaustion approach. */
    struct rsvp_psb* bypass_psb = NULL;
    for (int bkt = 0; bkt < 1024 && !bypass_psb; bkt++) {
        for (struct rsvp_psb* c = rsvp_psb_find_by_bucket(bkt); c; c = c->next_hash) {
            if (ntohs(c->key.session.tunnel_id) == bypass_tunnel_id &&
                c->is_bypass_tunnel) {
                bypass_psb = c;
                break;
            }
        }
    }

    if (!bypass_psb) {
        LOG_WARN("FRR: Bypass PSB not found for TunnelID %u", bypass_tunnel_id);
        return RSVP_ERR_NOT_FOUND;
    }

    /* Verify the bypass tunnel has a functional reservation (RSB with label). */
    struct rsvp_rsb* bypass_rsb = rsvp_rsb_find(&bypass_psb->key);
    if (!bypass_rsb || bypass_rsb->label_out == 0) {
        LOG_WARN("FRR: Bypass tunnel [TunnelID: %u] has no active RESV or "
                 "label_out=0 — protection cannot be armed",
                 bypass_tunnel_id);
        return RSVP_ERR_FRR_NOT_CONFIGURED;
    }

    protected_psb->frr_mode         = frr_mode;
    protected_psb->bypass_tunnel_id = bypass_tunnel_id;
    protected_psb->bypass_psb       = bypass_psb;

    LOG_INFO("FRR: Protection armed for TunnelID %u → bypass TunnelID %u "
             "(label_out=%u)",
             tunnel_id, bypass_tunnel_id, bypass_rsb->label_out);
    return RSVP_SUCCESS;
}

/* ---- rsvp_frr_trigger --------------------------------------------------- */

void rsvp_frr_trigger(uint32_t failed_ifindex) {
    LOG_WARN("FRR TRIGGER: Link failure detected on IfIndex %u — "
             "scanning for protected LSPs",
             failed_ifindex);

    int switched = 0;

    /* Walk the entire PSB hash table looking for LSPs that egress via the
     * failed interface and have facility-backup FRR configured. */
    for (int bucket = 0; bucket < 1024; bucket++) {
        struct rsvp_psb* psb = rsvp_psb_find_by_bucket(bucket);
        while (psb) {
            struct rsvp_psb* next = psb->next_hash;

            if (psb->ifindex_out == failed_ifindex &&
                psb->frr_mode   == RSVP_FRR_FACILITY &&
                psb->bypass_psb != NULL &&
                !psb->frr_active &&
                !psb->is_bypass_tunnel) {

                struct rsvp_psb* bp  = psb->bypass_psb;
                struct rsvp_rsb* brsb = rsvp_rsb_find(&bp->key);

                if (!brsb || brsb->label_out == 0) {
                    LOG_WARN("FRR: Bypass for TunnelID %u has no label — "
                             "cannot switch",
                             ntohs(psb->key.session.tunnel_id));
                    psb = next;
                    continue;
                }

                /* Reroute: reprogram MPLS forwarding to use the bypass label. */
                struct rsvp_rsb* rsb = rsvp_rsb_find(&psb->key);
                if (rsb) {
                    struct in_addr bypass_nh  = brsb->next_hop.neighbor_addr;
                    struct in_addr dest_tmp   = psb->key.session.dest_addr;
                    uint32_t       bypass_out = ntohl(brsb->next_hop.logical_interface);

                    LOG_INFO("FRR: Switching TunnelID %u to bypass TunnelID %u "
                             "[label_in=%u → bypass_label_out=%u, "
                             "nexthop=%s, if=%u]",
                             ntohs(psb->key.session.tunnel_id),
                             ntohs(bp->key.session.tunnel_id),
                             rsb->label_in, brsb->label_out,
                             inet_ntoa(bypass_nh), bypass_out);

                    hal_mpls_install(rsb->label_in, brsb->label_out,
                                     bypass_out, &bypass_nh, &dest_tmp);
                }

                psb->frr_active   = true;
                psb->ifindex_out  = bp->ifindex_out;
                switched++;

                /* Send PATH with LOCAL_PROTECTION_IN_USE so ingress and
                 * upstream nodes update their RRO flags. */
                send_path_downstream(psb);

                LOG_INFO("FRR: TunnelID %u switched to bypass path — "
                         "traffic rerouted",
                         ntohs(psb->key.session.tunnel_id));
            }

            psb = next;
        }
    }

    if (switched == 0) {
        LOG_INFO("FRR: No protected LSPs found for IfIndex %u", failed_ifindex);
    } else {
        LOG_INFO("FRR: Switched %d LSP(s) to bypass paths for IfIndex %u",
                 switched, failed_ifindex);
    }
}

/* ---- rsvp_teardown_path ------------------------------------------------- */

void rsvp_teardown_path(uint16_t tunnel_id, uint16_t lsp_id) {
    struct rsvp_psb* psb = rsvp_psb_find_by_id(tunnel_id, lsp_id);
    if (!psb) {
        LOG_WARN("Teardown: LSP not found [TunnelID: %u, LSPID: %u]",
                 tunnel_id, lsp_id);
        return;
    }
    LOG_INFO("Tearing down LSP [TunnelID: %u, LSPID: %u]", tunnel_id, lsp_id);
    rsvp_psb_cleanup(psb, true);
}

/* ---- rsvp_state_machine_shutdown ---------------------------------------- */

void rsvp_state_machine_shutdown(void) {
    LOG_WARN("RSVP state machine shutting down — "
             "sending PathTear/ResvTear for all active LSPs");

    /* Walk all buckets and clean up every PSB.  rsvp_psb_cleanup sends
     * PathTear downstream before freeing, giving peers a chance to flush
     * soft-state immediately rather than waiting for their cleanup timers. */
    for (int bucket = 0; bucket < 1024; bucket++) {
        struct rsvp_psb* psb;
        while ((psb = rsvp_psb_find_by_bucket(bucket)) != NULL) {
            LOG_INFO("  - Shutdown: tearing down TunnelID %u",
                     ntohs(psb->key.session.tunnel_id));
            rsvp_psb_cleanup(psb, true);
        }
    }

    LOG_INFO("RSVP state machine shutdown complete");
}
