/**
 * @file rsvp_hello.c
 * @brief RSVP Hello — neighbor liveness detection (RFC 3209 §5.3).
 *
 * Each configured neighbor gets:
 *   - A periodic hello_timer that fires every hello_interval_ms and sends a Hello REQUEST.
 *   - A dead_timer that fires after dead_interval_ms of silence; when it fires the neighbor
 *     is declared DOWN and rsvp_frr_trigger() is called for the neighbor's interface so that
 *     any protected LSPs switch to their bypass immediately.
 *
 * Instance ID rules (RFC 3209 §5.3):
 *   - src_instance: a non-zero 32-bit value unique to this node for each neighbor.
 *     Generated once at rsvp_hello_add_neighbor() time from rand() and stays fixed.
 *     A change in src_instance received from a peer signals a node restart.
 *   - dst_instance: the last src_instance received from the peer; 0 until first Hello.
 *
 * Hello messages do NOT carry the IP Router Alert Option (RFC 3209 §5.3 explicitly
 * says Hellos are sent directly to the neighbor's IP, not multicast / RA).
 */

#include "rsvp_hello.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/rsvp_log.h"
#include "common/rsvp_protocol.h"
#include "rsvp_builder.h"
#include "rsvp_dispatcher.h"
#include "rsvp_state_machine.h"

/* ---- Module-level state ------------------------------------------------- */

static struct rsvp_neighbor g_neighbors[RSVP_MAX_NEIGHBORS];
static int                  g_nbor_count = 0;

/* ---- Forward declarations ----------------------------------------------- */

static void hello_timer_cb(void* arg);
static void dead_timer_cb(void* arg);
static void send_hello(struct rsvp_neighbor* nbor, uint8_t c_type);
static const char* state_str(rsvp_nbor_state_t s);

/* ---- Lifecycle ---------------------------------------------------------- */

void rsvp_hello_init(void) {
    memset(g_neighbors, 0, sizeof(g_neighbors));
    g_nbor_count = 0;
    LOG_INFO("RSVP Hello subsystem initialized (max neighbors: %d)", RSVP_MAX_NEIGHBORS);
}

void rsvp_hello_shutdown(void) {
    LOG_INFO("RSVP Hello subsystem shutting down (%d neighbor(s))", g_nbor_count);
    for (int i = 0; i < g_nbor_count; i++) {
        struct rsvp_neighbor* n = &g_neighbors[i];
        if (!n->active) continue;
        rsvp_timer_stop(&n->hello_timer);
        rsvp_timer_stop(&n->dead_timer);
    }
    memset(g_neighbors, 0, sizeof(g_neighbors));
    g_nbor_count = 0;
}

/* ---- Neighbor management ------------------------------------------------ */

struct rsvp_neighbor* rsvp_hello_find_neighbor(struct in_addr* addr) {
    if (!addr) return NULL;
    for (int i = 0; i < g_nbor_count; i++) {
        if (g_neighbors[i].active && g_neighbors[i].addr.s_addr == addr->s_addr)
            return &g_neighbors[i];
    }
    return NULL;
}

struct rsvp_neighbor* rsvp_hello_add_neighbor(struct in_addr* addr,
                                               struct in_addr* local_addr,
                                               uint32_t ifindex) {
    if (!addr || !local_addr) return NULL;

    /* Return existing entry if already tracked */
    struct rsvp_neighbor* existing = rsvp_hello_find_neighbor(addr);
    if (existing) {
        LOG_DEBUG("Hello: neighbor %s already tracked", inet_ntoa(*addr));
        return existing;
    }

    if (g_nbor_count >= RSVP_MAX_NEIGHBORS) {
        LOG_ERROR("Hello: neighbor table full (max %d) — cannot add %s",
                  RSVP_MAX_NEIGHBORS, inet_ntoa(*addr));
        return NULL;
    }

    struct rsvp_neighbor* n = &g_neighbors[g_nbor_count++];
    memset(n, 0, sizeof(*n));

    n->addr         = *addr;
    n->local_addr   = *local_addr;
    n->ifindex      = ifindex;
    n->state        = RSVP_NBOR_IDLE;
    n->hello_interval_ms = RSVP_HELLO_INTERVAL_MS;
    n->dead_interval_ms  = RSVP_HELLO_INTERVAL_MS * RSVP_HELLO_DEAD_FACTOR;
    n->active       = true;

    /* Generate a random non-zero src_instance (RFC 3209 §5.3) */
    uint32_t inst = 0;
    while (inst == 0)
        inst = (uint32_t)rand();
    n->src_instance = inst;

    char addr_str[INET_ADDRSTRLEN], local_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr,       addr_str,  sizeof(addr_str));
    inet_ntop(AF_INET, local_addr, local_str, sizeof(local_str));

    LOG_INFO("Hello: adding neighbor %s (local %s, ifindex %u, src_instance 0x%08X)",
             addr_str, local_str, ifindex, n->src_instance);

    /* Start the periodic Hello transmit timer immediately */
    rsvp_timer_start(&n->hello_timer, RSVP_TIMER_REFRESH,
                     n->hello_interval_ms, hello_timer_cb, n);

    return n;
}

/* ---- Timer callbacks ---------------------------------------------------- */

/* Fires every hello_interval_ms — sends a Hello REQUEST and restarts itself. */
static void hello_timer_cb(void* arg) {
    struct rsvp_neighbor* n = (struct rsvp_neighbor*)arg;
    if (!n || !n->active) return;

    send_hello(n, RSVP_HELLO_CTYPE_REQUEST);

    /* Reschedule for the next interval */
    rsvp_timer_start(&n->hello_timer, RSVP_TIMER_REFRESH,
                     n->hello_interval_ms, hello_timer_cb, n);
}

/* Fires after dead_interval_ms without receiving any Hello from the neighbor. */
static void dead_timer_cb(void* arg) {
    struct rsvp_neighbor* n = (struct rsvp_neighbor*)arg;
    if (!n || !n->active) return;

    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &n->addr, addr_str, sizeof(addr_str));

    LOG_WARN("Hello: neighbor %s DEAD (no Hello in %u ms) — state: %s → DOWN",
             addr_str, n->dead_interval_ms, state_str(n->state));

    n->state    = RSVP_NBOR_DOWN;
    n->up_since = 0;

    /* Trigger FRR switchover for all LSPs egressing this neighbor's interface.
     * This ensures protected LSPs switch to their bypass within this same event loop
     * tick rather than waiting for the next PATH refresh cycle. */
    LOG_WARN("Hello: triggering FRR for interface ifindex %u due to neighbor %s DOWN",
             n->ifindex, addr_str);
    rsvp_frr_trigger(n->ifindex);
}

/* ---- Packet construction and transmission ------------------------------- */

static void send_hello(struct rsvp_neighbor* nbor, uint8_t c_type) {
    uint8_t buf[128];
    struct rsvp_builder b;

    rsvp_builder_init(&b, buf, sizeof(buf), RSVP_MSG_HELLO);

    struct rsvp_hello_obj obj;
    obj.src_instance = htonl(nbor->src_instance);
    obj.dst_instance = htonl(nbor->dst_instance);

    if (rsvp_builder_add_obj(&b, RSVP_CLASS_HELLO, c_type,
                              &obj, sizeof(obj)) != 0) {
        LOG_ERROR("Hello: builder overflow building Hello toward %s", inet_ntoa(nbor->addr));
        return;
    }

    size_t msg_len = rsvp_builder_finalize(&b);

    /* Hello messages are sent directly to the neighbor IP (no Router Alert Option). */
    rsvp_error_t err = rsvp_send_packet(&nbor->local_addr, &nbor->addr,
                                         buf, msg_len, false);
    if (err == RSVP_SUCCESS) {
        nbor->hellos_sent++;
        LOG_DEBUG("Hello: sent %s to %s (src_inst=0x%08X dst_inst=0x%08X)",
                  (c_type == RSVP_HELLO_CTYPE_REQUEST) ? "REQUEST" : "ACK",
                  inet_ntoa(nbor->addr),
                  nbor->src_instance, nbor->dst_instance);
    } else {
        LOG_ERROR("Hello: failed to send Hello to %s (err %d)", inet_ntoa(nbor->addr), err);
    }
}

/* ---- Receive processing ------------------------------------------------- */

void rsvp_hello_recv(struct in_addr* src, uint32_t rx_src_instance,
                      uint32_t rx_dst_instance, uint8_t c_type) {
    if (!src) return;

    char src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, src, src_str, sizeof(src_str));

    struct rsvp_neighbor* n = rsvp_hello_find_neighbor(src);
    if (!n) {
        /* Auto-create an entry for dynamically discovered neighbors.
         * We don't know the local address yet; use 0 as placeholder — the state
         * machine will update it if needed.  This allows Hellos from a peer that
         * started first to be handled gracefully without pre-configuration. */
        struct in_addr zero = {0};
        n = rsvp_hello_add_neighbor(src, &zero, 0);
        if (!n) {
            LOG_WARN("Hello: received Hello from unknown neighbor %s — table full, dropping",
                     src_str);
            return;
        }
        LOG_INFO("Hello: auto-created neighbor entry for %s", src_str);
    }

    n->hellos_rcvd++;
    n->last_hello_rx = time(NULL);

    /* Restart detection: if we already know this neighbor's instance but it changed,
     * the neighbor has restarted.  Declare DOWN then transition back to IDLE so we
     * re-establish liveness cleanly. */
    if (n->dst_instance != 0 && rx_src_instance != n->dst_instance) {
        LOG_WARN("Hello: neighbor %s RESTARTED (old inst=0x%08X new inst=0x%08X) — re-establishing",
                 src_str, n->dst_instance, rx_src_instance);
        n->state        = RSVP_NBOR_IDLE;
        n->up_since     = 0;
        n->dst_instance = 0;
        rsvp_frr_trigger(n->ifindex);
    }

    /* Store the neighbor's advertised instance ID */
    n->dst_instance = rx_src_instance;

    /* Reset the dead timer every time we hear from the neighbor */
    rsvp_timer_stop(&n->dead_timer);
    rsvp_timer_start(&n->dead_timer, RSVP_TIMER_CLEANUP,
                     n->dead_interval_ms, dead_timer_cb, n);

    /* Transition to UP if not already */
    if (n->state != RSVP_NBOR_UP) {
        /* RFC 3209 §5.3: we consider the adjacency UP once we receive a Hello
         * where dst_instance == our src_instance (bidirectional confirmation).
         * If dst_instance is 0 the peer hasn't seen us yet — we're still one-way,
         * but we optimistically go UP to avoid delays on first contact. */
        rsvp_nbor_state_t old_state = n->state;
        n->state    = RSVP_NBOR_UP;
        n->up_since = time(NULL);
        LOG_INFO("Hello: neighbor %s %s → UP (src_inst=0x%08X dst_inst=0x%08X)",
                 src_str, state_str(old_state), rx_src_instance, rx_dst_instance);
    }

    /* If the peer sent a REQUEST, reply with an ACK */
    if (c_type == RSVP_HELLO_CTYPE_REQUEST) {
        LOG_DEBUG("Hello: received REQUEST from %s — sending ACK", src_str);
        send_hello(n, RSVP_HELLO_CTYPE_ACK);
    } else {
        LOG_DEBUG("Hello: received ACK from %s (state: %s)", src_str, state_str(n->state));
    }
}

/* ---- Display ------------------------------------------------------------ */

static const char* state_str(rsvp_nbor_state_t s) {
    switch (s) {
        case RSVP_NBOR_IDLE: return "IDLE";
        case RSVP_NBOR_UP:   return "UP";
        case RSVP_NBOR_DOWN: return "DOWN";
        default:             return "UNKNOWN";
    }
}

void rsvp_hello_dump(void) {
    int active_count = 0;
    for (int i = 0; i < g_nbor_count; i++)
        if (g_neighbors[i].active) active_count++;

    if (active_count == 0) {
        printf("No RSVP neighbors configured.\n");
        return;
    }

    printf("%-17s %-17s %-6s %-8s %-10s %-10s %-25s\n",
           "Neighbor", "Local Addr", "State", "Iface", "Hellos Tx", "Hellos Rx", "Up Since");
    printf("%-17s %-17s %-6s %-8s %-10s %-10s %-25s\n",
           "--------", "----------", "-----", "-----", "---------", "---------", "--------");

    for (int i = 0; i < g_nbor_count; i++) {
        struct rsvp_neighbor* n = &g_neighbors[i];
        if (!n->active) continue;

        char addr_str[INET_ADDRSTRLEN], local_str[INET_ADDRSTRLEN], up_str[32];
        inet_ntop(AF_INET, &n->addr,       addr_str,  sizeof(addr_str));
        inet_ntop(AF_INET, &n->local_addr, local_str, sizeof(local_str));

        if (n->state == RSVP_NBOR_UP && n->up_since) {
            struct tm* tm_info = localtime(&n->up_since);
            strftime(up_str, sizeof(up_str), "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            snprintf(up_str, sizeof(up_str), "-");
        }

        printf("%-17s %-17s %-6s %-8u %-10llu %-10llu %-25s\n",
               addr_str, local_str,
               state_str(n->state),
               n->ifindex,
               (unsigned long long)n->hellos_sent,
               (unsigned long long)n->hellos_rcvd,
               up_str);
    }
}
