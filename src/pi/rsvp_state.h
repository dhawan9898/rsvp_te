/**
 * @file rsvp_state.h
 * @brief RSVP State Block Definitions.
 * @details Defines the structures used to store RSVP Path and Reservation state, as well as the composite keys used for state lookup.
 */

#ifndef RSVP_STATE_H
#define RSVP_STATE_H

#include <stdbool.h>

#include "rsvp_protocol.h"
#include "rsvp_timers.h"

/* Forward declarations */
struct rsvp_psb;
struct rsvp_rsb;

/**
 * @brief Key for Path State Block (PSB)
 * @details A unique identifier for an RSVP session, combining the Session and Sender Template objects.
 */
struct rsvp_path_key {
    struct rsvp_session_ipv4 session; /**< The session parameters (Dest Address, Tunnel ID) */
    struct rsvp_sender_ipv4 sender;   /**< The sender parameters (Source Address, LSP ID) */
};

/**
 * @brief Path State Block (PSB)
 * @details Stores the state created by an incoming RSVP Path message.
 */
struct rsvp_psb {
    struct rsvp_path_key key; /**< Unique key identifying this PSB */

    /* Protocol State */
    struct rsvp_hop_ipv4 prev_hop; /**< Previous Hop (PHOP) information */
    uint32_t ifindex_in;           /**< Ingress interface index */
    uint32_t ifindex_out;          /**< Egress interface index */
    char* lsp_name;                /**< Name of the LSP tunnel */

    /* State Management */
    rsvp_timer_t cleanup_timer; /**< Timer for expiring the state */
    rsvp_timer_t refresh_timer; /**< Timer for sending periodic refresh messages */
    uint32_t refresh_ms;        /**< Configured refresh interval in milliseconds */
    uint8_t ttl;                /**< IP TTL value to use for outbound packets */
    uint8_t refresh_count;      /**< Number of refreshes sent */
    bool is_ingress;            /**< Flag indicating if this node is the ingress for the LSP */

    /* Chaining for Hash Table and Interface Lists */
    struct rsvp_psb* next_hash; /**< Next PSB in the hash bucket */
    struct rsvp_psb* next_if;   /**< Next PSB associated with the same interface */

    struct rsvp_rsb* associated_rsb; /**< Pointer to the matching RSB, if one exists */
};

/**
 * @brief Resv State Block (RSB)
 * @details Stores the state created by an incoming RSVP Resv message.
 */
struct rsvp_rsb {
    struct rsvp_path_key key; /**< Unique key identifying this RSB (matches the PSB key) */

    /* Protocol State */
    struct rsvp_hop_ipv4 next_hop; /**< Next Hop (NHOP) information */
    uint32_t label_in;             /**< MPLS label allocated by this node */
    uint32_t label_out;            /**< MPLS label received from the downstream node */

    /* State Management */
    rsvp_timer_t cleanup_timer; /**< Timer for expiring the state */
    rsvp_timer_t refresh_timer; /**< Timer for sending periodic refresh messages */
    uint32_t refresh_ms;        /**< Configured refresh interval in milliseconds */
    uint8_t ttl;                /**< IP TTL value to use for outbound packets */
    uint8_t refresh_count;      /**< Number of refreshes sent */
    uint32_t hal_handle;        /**< Handle to the programmed hardware/datapath state */

    /* Chaining */
    struct rsvp_rsb* next_hash;      /**< Next RSB in the hash bucket */
    struct rsvp_psb* associated_psb; /**< Pointer to the associated PSB */
};

#endif /* RSVP_STATE_H */
