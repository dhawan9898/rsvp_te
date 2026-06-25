/**
 * @file rsvp_if.c
 * @brief RSVP-TE Interface Management — implementation.
 * @details Manages per-interface RSVP state including enable/disable, bandwidth configuration
 *          (total, reservable, reserved per priority), and CLI display helpers.
 */

#include "rsvp_if.h"

#include <stdio.h>
#include <string.h>

#include "common/rsvp_log.h"

static struct rsvp_if g_if_table[RSVP_MAX_IF];
static int            g_if_count = 0;

/* ---- Lifecycle ---------------------------------------------------------- */

void rsvp_if_init(void) {
    memset(g_if_table, 0, sizeof(g_if_table));
    g_if_count = 0;
    LOG_INFO("RSVP interface table initialized (capacity: %d)", RSVP_MAX_IF);
}

void rsvp_if_shutdown(void) {
    LOG_INFO("RSVP interface table shutdown (%d interface(s) configured)", g_if_count);
    memset(g_if_table, 0, sizeof(g_if_table));
    g_if_count = 0;
}

/* ---- Lookup ------------------------------------------------------------- */

struct rsvp_if* rsvp_if_get(int ifindex) {
    for (int i = 0; i < g_if_count; i++) {
        if (g_if_table[i].active && g_if_table[i].ifindex == ifindex)
            return &g_if_table[i];
    }
    return NULL;
}

struct rsvp_if* rsvp_if_get_by_name(const char* name) {
    if (!name) return NULL;
    for (int i = 0; i < g_if_count; i++) {
        if (g_if_table[i].active && strncmp(g_if_table[i].name, name, IF_NAMESIZE) == 0)
            return &g_if_table[i];
    }
    return NULL;
}

/* Find an existing entry or allocate a fresh slot. */
static struct rsvp_if* rsvp_if_find_or_create(const char* name) {
    struct rsvp_if* iface = rsvp_if_get_by_name(name);
    if (iface) return iface;

    if (g_if_count >= RSVP_MAX_IF) {
        LOG_ERROR("Interface table full (max %d) — cannot add %s", RSVP_MAX_IF, name);
        return NULL;
    }

    iface = &g_if_table[g_if_count++];
    memset(iface, 0, sizeof(*iface));
    strncpy(iface->name, name, IF_NAMESIZE - 1);
    iface->ifindex            = (int)if_nametoindex(name); /* 0 if not yet a kernel iface */
    iface->hello_interval_ms  = 5000;
    iface->active             = true;
    return iface;
}

/* ---- Enable / Disable --------------------------------------------------- */

struct rsvp_if* rsvp_if_enable(const char* name) {
    struct rsvp_if* iface = rsvp_if_find_or_create(name);
    if (!iface) return NULL;

    /* Refresh ifindex in case the interface was added after init */
    unsigned int idx = if_nametoindex(name);
    if (idx) iface->ifindex = (int)idx;

    iface->rsvp_enabled = true;
    LOG_INFO("RSVP enabled on interface %s (ifindex %d)", iface->name, iface->ifindex);
    return iface;
}

void rsvp_if_disable(const char* name) {
    struct rsvp_if* iface = rsvp_if_get_by_name(name);
    if (!iface) {
        LOG_WARN("RSVP disable: interface '%s' not found in RSVP table", name);
        return;
    }
    iface->rsvp_enabled = false;
    LOG_INFO("RSVP disabled on interface %s", name);
}

/* ---- Bandwidth management ---------------------------------------------- */

void rsvp_if_set_bandwidth(const char* name, double total_bw, double reservable_bw) {
    struct rsvp_if* iface = rsvp_if_find_or_create(name);
    if (!iface) return;

    iface->total_bw      = total_bw;
    iface->reservable_bw = reservable_bw;
    LOG_INFO("Interface %s: total_bw=%.0f bps  reservable_bw=%.0f bps",
             name, total_bw, reservable_bw);
}

void rsvp_if_reserve_bw(int ifindex, uint8_t priority, double bw) {
    if (priority >= RSVP_NUM_PRIORITIES) {
        LOG_WARN("rsvp_if_reserve_bw: invalid priority %u", priority);
        return;
    }
    struct rsvp_if* iface = rsvp_if_get(ifindex);
    if (!iface) return;

    iface->reserved_bw[priority] += bw;
    LOG_DEBUG("Interface %s prio %u: +%.0f bps reserved (total at prio: %.0f bps)",
              iface->name, priority, bw, iface->reserved_bw[priority]);
}

void rsvp_if_release_bw(int ifindex, uint8_t priority, double bw) {
    if (priority >= RSVP_NUM_PRIORITIES) {
        LOG_WARN("rsvp_if_release_bw: invalid priority %u", priority);
        return;
    }
    struct rsvp_if* iface = rsvp_if_get(ifindex);
    if (!iface) return;

    iface->reserved_bw[priority] -= bw;
    if (iface->reserved_bw[priority] < 0.0)
        iface->reserved_bw[priority] = 0.0;

    LOG_DEBUG("Interface %s prio %u: -%.0f bps released (remaining: %.0f bps)",
              iface->name, priority, bw, iface->reserved_bw[priority]);
}

double rsvp_if_available_bw(int ifindex, uint8_t priority) {
    if (priority >= RSVP_NUM_PRIORITIES) return 0.0;

    struct rsvp_if* iface = rsvp_if_get(ifindex);
    if (!iface) return 0.0;

    /* Sum reservations at all priorities higher than or equal to the requested one.
     * RFC 2209: a request at priority P competes against all reservations at priority
     * 0 through P, so we accumulate them all before comparing against reservable_bw. */
    double total_reserved = 0.0;
    for (int p = 0; p <= priority; p++)
        total_reserved += iface->reserved_bw[p];

    double avail = iface->reservable_bw - total_reserved;
    return (avail > 0.0) ? avail : 0.0;
}

/* ---- Display helpers ---------------------------------------------------- */

/* Format bps into a human-readable string (e.g. "1.50 Gbps"). */
static void format_bps(double bps, char* buf, size_t n) {
    if      (bps >= 1e9) snprintf(buf, n, "%.2f Gbps", bps / 1e9);
    else if (bps >= 1e6) snprintf(buf, n, "%.2f Mbps", bps / 1e6);
    else if (bps >= 1e3) snprintf(buf, n, "%.2f Kbps", bps / 1e3);
    else                 snprintf(buf, n, "%.0f bps",  bps);
}

void rsvp_if_dump(void) {
    int active_count = 0;
    for (int i = 0; i < g_if_count; i++)
        if (g_if_table[i].active) active_count++;

    if (active_count == 0) {
        printf("No RSVP interfaces configured.\n");
        return;
    }

    printf("%-12s %-8s %-7s %-18s %-18s\n",
           "Interface", "ifindex", "RSVP", "Total BW", "Reservable BW");
    printf("%-12s %-8s %-7s %-18s %-18s\n",
           "---------", "-------", "----", "--------", "-------------");

    char buf1[32], buf2[32];
    for (int i = 0; i < g_if_count; i++) {
        struct rsvp_if* iface = &g_if_table[i];
        if (!iface->active) continue;
        format_bps(iface->total_bw,      buf1, sizeof(buf1));
        format_bps(iface->reservable_bw, buf2, sizeof(buf2));
        printf("%-12s %-8d %-7s %-18s %-18s\n",
               iface->name, iface->ifindex,
               iface->rsvp_enabled ? "up" : "down",
               buf1, buf2);
    }
}

void rsvp_if_dump_one(const char* name) {
    struct rsvp_if* iface = rsvp_if_get_by_name(name);
    if (!iface) {
        printf("Interface '%s' not found in RSVP table.\n", name);
        return;
    }

    char buf[32];
    printf("Interface       : %s\n", iface->name);
    printf("  ifindex       : %d\n", iface->ifindex);
    printf("  RSVP          : %s\n", iface->rsvp_enabled ? "enabled" : "disabled");
    printf("  Hello interval: %u ms\n", iface->hello_interval_ms);
    format_bps(iface->total_bw, buf, sizeof(buf));
    printf("  Total BW      : %s\n", buf);
    format_bps(iface->reservable_bw, buf, sizeof(buf));
    printf("  Reservable BW : %s\n", buf);
    printf("  Reserved BW per priority:\n");
    for (int p = 0; p < RSVP_NUM_PRIORITIES; p++) {
        format_bps(iface->reserved_bw[p], buf, sizeof(buf));
        printf("    Priority %d   : %s\n", p, buf);
    }
    format_bps(rsvp_if_available_bw(iface->ifindex, 0), buf, sizeof(buf));
    printf("  Available BW  : %s (at priority 0)\n", buf);
}
