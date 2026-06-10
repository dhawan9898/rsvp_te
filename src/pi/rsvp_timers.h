#ifndef RSVP_TIMERS_H
#define RSVP_TIMERS_H

#include <stdint.h>
#include <stdbool.h>

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
typedef void (*rsvp_timer_cb)(void *arg);

/**
 * Initialize the timer management system.
 */
void rsvp_timer_init(void);

/**
 * Start a timer.
 * Returns a unique timer ID.
 */
uint32_t rsvp_timer_start(rsvp_timer_type_t type, uint32_t timeout_ms, rsvp_timer_cb cb, void *arg);

/**
 * Stop a timer by ID.
 */
void rsvp_timer_stop(uint32_t timer_id);

/**
 * Reset/Restart an existing timer.
 */
void rsvp_timer_reset(uint32_t timer_id, uint32_t timeout_ms);

/**
 * Get all active timer file descriptors for polling.
 * Returns the number of fds added to the array.
 */
int rsvp_timer_get_fds(int *fds, int max_fds);

/**
 * Handle a timer expiration for a given fd.
 */
void rsvp_timer_handle_exp(int fd);

#endif /* RSVP_TIMERS_H */
