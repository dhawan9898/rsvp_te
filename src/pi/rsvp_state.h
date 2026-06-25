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

#define MAX_ERO_HOPS 32
#define MAX_RRO_HOPS 32

/**
 * @brief FRR protection mode for an LSP (RFC 4090).
 */
typedef enum {
    RSVP_FRR_NONE        = 0, /**< No FRR protection requested */
    RSVP_FRR_ONE_TO_ONE  = 1, /**< One-to-one backup: a dedicated detour LSP per protected LSP */
    RSVP_FRR_FACILITY    = 2, /**< Facility backup: traffic rerouted through a shared bypass tunnel */
} rsvp_frr_mode_t;

/* Forward declarations */
struct rsvp_psb;
struct rsvp_rsb;
struct rsvp_bsb;

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

    /* RSVP-TE Properties */
    struct rsvp_ero_ipv4_subobj ero[MAX_ERO_HOPS]; /**< Explicit Route Object */
    uint8_t ero_count;
    struct rsvp_ero_ipv4_subobj rro[MAX_RRO_HOPS]; /**< Record Route Object */
    uint8_t rro_count;
    struct rsvp_sender_tspec tspec;                /**< Traffic Specification */
    uint8_t setup_prio;                            /**< Setup Priority */
    uint8_t holding_prio;                          /**< Holding Priority */

    /* State Management */
    rsvp_timer_t cleanup_timer; /**< Timer for expiring the state if no refresh arrives */
    rsvp_timer_t refresh_timer; /**< Timer for sending periodic PATH refresh messages */
    uint32_t refresh_ms;        /**< Negotiated refresh interval in milliseconds */
    uint8_t ttl;                /**< IP TTL copied from the received PATH; used for forwarded messages */
    uint8_t refresh_count;      /**< Number of refresh cycles completed without state change */
    bool is_ingress;            /**< True when this node originated the PATH (head-end role) */

    /* Fast ReRoute state (RFC 4090) */
    rsvp_frr_mode_t frr_mode;        /**< Protection mode negotiated for this LSP */
    bool is_bypass_tunnel;           /**< True when this PSB represents a bypass/detour tunnel itself */
    bool frr_active;                 /**< True once FRR has triggered and traffic uses the backup path */
    uint16_t bypass_tunnel_id;       /**< Tunnel ID of the bypass PSB used in facility mode */
    struct rsvp_psb* bypass_psb;     /**< Direct pointer to the pre-established bypass PSB (facility mode) */
    uint32_t frr_bandwidth;          /**< Bandwidth (bps) this LSP needs protected */
    uint32_t frr_protected_ifindex;  /**< Egress interface this bypass covers (0 if not a bypass) */

    /* Chaining for Hash Table */
    struct rsvp_psb* next_hash; /**< Next PSB in the same hash bucket */
    struct rsvp_psb* next_if;   /**< Next PSB sharing the same ingress interface */

    struct rsvp_rsb* associated_rsb; /**< Matching RSB, or NULL if no reservation yet */
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

    /* Traffic Control & Merging */
    struct rsvp_sender_tspec flowspec; /**< Effective reservation flowspec */
    uint8_t style;                     /**< Reservation style (FF, SE, WF) */

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

/**
 * @brief Blockade State Block (BSB)
 * @details Used to prevent "Killer Reservations" (RFC 2209).
 */
struct rsvp_bsb {
    struct rsvp_path_key key; /**< Identifies (Session, Sender/PHOP) */

    /* Blockade State */
    struct rsvp_sender_tspec flowspec_qb; /**< Blockade Flowspec Qb */
    rsvp_timer_t blockade_timer;          /**< Blockade Timer Tb */

    /* Chaining */
    struct rsvp_bsb* next_hash; /**< Next BSB in hash bucket */
};

#endif /* RSVP_STATE_H */
