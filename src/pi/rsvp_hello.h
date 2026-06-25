/**
 * @file rsvp_hello.h
 * @brief RSVP Hello — neighbor liveness detection (RFC 3209 §5.3).
 * @details Manages a table of RSVP neighbors, sends periodic Hello REQUEST messages,
 *          responds with Hello ACK, and declares neighbors DOWN when the dead interval
 *          expires.  A DOWN event triggers rsvp_frr_trigger() for all LSPs through that
 *          neighbor so FRR switchover happens immediately.
 */

#ifndef RSVP_HELLO_H
#define RSVP_HELLO_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "rsvp_timers.h"

/** Hello REQUEST send interval (ms).  RFC 3209 recommends 5 s for most deployments. */
#define RSVP_HELLO_INTERVAL_MS  5000

/** Number of missed Hellos before a neighbor is declared DOWN (dead interval = 3 × interval). */
#define RSVP_HELLO_DEAD_FACTOR  3

/** Maximum number of simultaneously tracked RSVP neighbors. */
#define RSVP_MAX_NEIGHBORS      128

/**
 * @brief Neighbor liveness state.
 */
typedef enum {
    RSVP_NBOR_IDLE = 0, /**< No Hello exchange started yet */
    RSVP_NBOR_UP,       /**< Bidirectional Hello exchange confirmed */
    RSVP_NBOR_DOWN,     /**< Dead interval expired — neighbor unreachable */
} rsvp_nbor_state_t;

/**
 * @brief Per-neighbor RSVP Hello state block.
 */
struct rsvp_neighbor {
    struct in_addr    addr;              /**< Neighbor IP address */
    struct in_addr    local_addr;        /**< Local IP address on the link toward this neighbor */
    uint32_t          ifindex;           /**< Interface index toward this neighbor */

    /* Hello instance identifiers (RFC 3209 §5.3) */
    uint32_t          src_instance;      /**< Our stable instance ID sent in every Hello */
    uint32_t          dst_instance;      /**< Last src_instance received from this neighbor (0 = unknown) */

    /* State tracking */
    rsvp_nbor_state_t state;
    uint32_t          hello_interval_ms; /**< Send interval for Hellos toward this neighbor */
    uint32_t          dead_interval_ms;  /**< Inactivity deadline = DEAD_FACTOR × hello_interval */
    time_t            up_since;          /**< Timestamp when state last entered UP (0 if not UP) */
    time_t            last_hello_rx;     /**< Timestamp of last Hello received (0 if never) */
    uint64_t          hellos_sent;       /**< Total Hello REQUEST messages sent */
    uint64_t          hellos_rcvd;       /**< Total Hello messages received (REQUEST + ACK) */

    /* Timers */
    rsvp_timer_t      hello_timer;       /**< Periodic transmit timer */
    rsvp_timer_t      dead_timer;        /**< Inactivity expiry timer */

    /* Table chaining */
    struct rsvp_neighbor* next_hash;
    bool              active;
};

/**
 * @brief Initialize the Hello subsystem.
 * @details Must be called before any other rsvp_hello_* function.
 */
void rsvp_hello_init(void);

/**
 * @brief Register and start sending Hellos to a new neighbor.
 * @details Creates a neighbor entry and immediately starts the Hello timer.
 *          If the neighbor already exists, the existing entry is returned unchanged.
 * @param [in] addr      Neighbor IP address.
 * @param [in] local_addr Local IP address on the link facing this neighbor.
 * @param [in] ifindex   Interface index toward this neighbor.
 * @return Pointer to the neighbor entry, or NULL if the table is full.
 */
struct rsvp_neighbor* rsvp_hello_add_neighbor(struct in_addr* addr,
                                               struct in_addr* local_addr,
                                               uint32_t ifindex);

/**
 * @brief Look up a neighbor by IP address.
 * @return Pointer to the entry, or NULL if not found.
 */
struct rsvp_neighbor* rsvp_hello_find_neighbor(struct in_addr* addr);

/**
 * @brief Process a received Hello message.
 * @details Handles both REQUEST (c_type 1) and ACK (c_type 2) Hellos.
 *          Resets the dead timer, updates state to UP on first contact,
 *          detects neighbor restarts, and sends an ACK in response to a REQUEST.
 * @param [in] src              Source IP address of the Hello.
 * @param [in] rx_src_instance  src_instance field from the received Hello object.
 * @param [in] rx_dst_instance  dst_instance field from the received Hello object.
 * @param [in] c_type           RSVP_HELLO_CTYPE_REQUEST (1) or RSVP_HELLO_CTYPE_ACK (2).
 */
void rsvp_hello_recv(struct in_addr* src, uint32_t rx_src_instance,
                      uint32_t rx_dst_instance, uint8_t c_type);

/**
 * @brief Print a neighbor state table to stdout.
 */
void rsvp_hello_dump(void);

/**
 * @brief Stop all Hello timers and free neighbor state.
 * @details Called during graceful shutdown before the process exits.
 */
void rsvp_hello_shutdown(void);

#endif /* RSVP_HELLO_H */
