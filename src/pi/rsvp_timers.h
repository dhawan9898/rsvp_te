#ifndef RSVP_TIMERS_H
#define RSVP_TIMERS_H

#include <stdbool.h>
#include <stdint.h>
#include "wheel_timer.h"

/**
 * Timer types for RSVP.
 */
typedef enum {
    RSVP_TIMER_REFRESH, /* Send periodic refresh messages */
    RSVP_TIMER_CLEANUP, /* Expire state if no refresh received */
} rsvp_timer_type_t;

/**
 * Callback function for timer expiration.
 */
typedef void (*rsvp_timer_cb)(void* arg);

/**
 * Embedded Timer Structure
 */
typedef struct {
    timer_node_t node;
    rsvp_timer_type_t type;
    rsvp_timer_cb cb;
    void* arg;
    bool active;
} rsvp_timer_t;

/**
 * Initialize the timer management system.
 */
void rsvp_timer_init(void);

/**
 * Start a timer.
 */
void rsvp_timer_start(rsvp_timer_t* timer, rsvp_timer_type_t type, uint32_t timeout_ms, rsvp_timer_cb cb, void* arg);

/**
 * Stop a timer.
 */
void rsvp_timer_stop(rsvp_timer_t* timer);

/**
 * Reset/Restart an existing timer.
 * Returns true if successful.
 */
bool rsvp_timer_reset(rsvp_timer_t* timer, uint32_t timeout_ms);

/**
 * Get all active timer file descriptors for polling.
 * Returns the number of fds added to the array.
 */
int rsvp_timer_get_fds(int* fds, int max_fds);

/**
 * Handle a timer expiration for a given fd.
 */
void rsvp_timer_handle_exp(int fd);

#endif /* RSVP_TIMERS_H */