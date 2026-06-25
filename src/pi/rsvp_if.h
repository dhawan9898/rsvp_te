/**
 * @file rsvp_if.h
 * @brief RSVP-TE Interface Management.
 * @details Per-interface RSVP state: enable/disable, total/reservable/reserved bandwidth at
 *          each of the 8 RSVP preemption priorities (RFC 2209 §2.2).
 */

#ifndef RSVP_IF_H
#define RSVP_IF_H

#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>

/** Number of RSVP preemption priorities (0 = highest, 7 = lowest). */
#define RSVP_NUM_PRIORITIES 8

/** Maximum number of concurrently managed RSVP interfaces. */
#define RSVP_MAX_IF 64

/**
 * @brief Per-interface RSVP state block.
 */
struct rsvp_if {
    char     name[IF_NAMESIZE]; /**< Interface name (e.g., "eth0") */
    int      ifindex;           /**< Kernel interface index */
    bool     rsvp_enabled;      /**< True when RSVP signaling is active on this interface */
    double   total_bw;          /**< Physical link capacity in bps */
    double   reservable_bw;     /**< Maximum reservable bandwidth in bps */
    double   reserved_bw[RSVP_NUM_PRIORITIES]; /**< Reserved bps at each setup priority */
    uint32_t hello_interval_ms; /**< Hello send interval in ms (default 5000) */
    bool     active;            /**< True when this slot is in use */
};

/**
 * @brief Initialize the interface table.
 * @details Must be called once before any other rsvp_if_* function.
 */
void rsvp_if_init(void);

/**
 * @brief Look up an interface by kernel index.
 * @return Pointer to the rsvp_if entry, or NULL if not found.
 */
struct rsvp_if* rsvp_if_get(int ifindex);

/**
 * @brief Look up an interface by name.
 * @return Pointer to the rsvp_if entry, or NULL if not found.
 */
struct rsvp_if* rsvp_if_get_by_name(const char* name);

/**
 * @brief Enable RSVP on an interface, creating an entry if it does not exist.
 * @return Pointer to the rsvp_if entry, or NULL on table-full error.
 */
struct rsvp_if* rsvp_if_enable(const char* name);

/**
 * @brief Disable RSVP on an interface (entry remains, rsvp_enabled = false).
 */
void rsvp_if_disable(const char* name);

/**
 * @brief Set the total and reservable bandwidth on an interface.
 * @param [in] name Interface name.
 * @param [in] total_bw Link capacity in bps.
 * @param [in] reservable_bw Maximum bandwidth that may be reserved in bps.
 */
void rsvp_if_set_bandwidth(const char* name, double total_bw, double reservable_bw);

/**
 * @brief Record a new bandwidth reservation at a given setup priority.
 * @details Called when a RESV is installed on this interface.
 * @param [in] ifindex Kernel interface index.
 * @param [in] priority Setup priority (0–7).
 * @param [in] bw Bandwidth to reserve in bps.
 */
void rsvp_if_reserve_bw(int ifindex, uint8_t priority, double bw);

/**
 * @brief Release a previously reserved bandwidth allocation.
 * @details Called when an LSP is torn down on this interface.
 * @param [in] ifindex Kernel interface index.
 * @param [in] priority Setup priority (0–7).
 * @param [in] bw Bandwidth to release in bps.
 */
void rsvp_if_release_bw(int ifindex, uint8_t priority, double bw);

/**
 * @brief Compute available bandwidth at a given priority level.
 * @details Sums reserved_bw for all priorities 0..priority and subtracts from reservable_bw.
 *          This reflects the preemption model: higher-priority reservations compete for the
 *          same pool as lower-priority ones.
 * @param [in] ifindex Kernel interface index.
 * @param [in] priority Setup priority (0–7).
 * @return Available bps, clamped to zero.
 */
double rsvp_if_available_bw(int ifindex, uint8_t priority);

/**
 * @brief Print a summary table of all configured RSVP interfaces.
 */
void rsvp_if_dump(void);

/**
 * @brief Print detailed RSVP state for a single interface.
 * @param [in] name Interface name.
 */
void rsvp_if_dump_one(const char* name);

/**
 * @brief Shut down the interface table and release all resources.
 */
void rsvp_if_shutdown(void);

#endif /* RSVP_IF_H */
