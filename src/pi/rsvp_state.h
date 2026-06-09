#ifndef RSVP_STATE_H
#define RSVP_STATE_H

#include "rsvp_protocol.h"
#include <stdbool.h>

/* Forward declarations */
struct rsvp_psb;
struct rsvp_rsb;

/**
 * Key for Path State Block (PSB)
 */
struct rsvp_path_key {
    struct rsvp_session_ipv4 session;
    struct rsvp_sender_ipv4  sender;
};

/**
 * Path State Block (PSB)
 */
struct rsvp_psb {
    struct rsvp_path_key key;
    
    /* Protocol State */
    struct rsvp_hop_ipv4 prev_hop;
    uint32_t             ifindex_in;
    uint32_t             ifindex_out;
    
    /* State Management */
    uint32_t             cleanup_timer_id;
    uint32_t             refresh_timer_id;
    
    /* Chaining for Hash Table and Interface Lists */
    struct rsvp_psb      *next_hash;
    struct rsvp_psb      *next_if;
    
    struct rsvp_rsb      *associated_rsb;
};

/**
 * Resv State Block (RSB)
 */
struct rsvp_rsb {
    struct rsvp_path_key key; /* Same key as PSB for 1-to-1 mapping */
    
    /* Protocol State */
    struct rsvp_hop_ipv4 next_hop;
    uint32_t             label_in;  /* Label we allocated */
    uint32_t             label_out; /* Label from downstream */
    
    /* State Management */
    uint32_t             cleanup_timer_id;
    uint32_t             hal_handle; /* Handle to programmed HW state */
    
    /* Chaining */
    struct rsvp_rsb      *next_hash;
    struct rsvp_psb      *associated_psb;
};

#endif /* RSVP_STATE_H */
