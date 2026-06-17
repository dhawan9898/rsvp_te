/**
 * @file rsvp_timers.h
 * @brief RSVP Timer Management.
 * @details Provides an interface to start, stop, and manage periodic refresh and state cleanup timers.
 */

#ifndef RSVP_TIMERS_H
#define RSVP_TIMERS_H

#include <stdbool.h>
#include <stdint.h>
#include "wheel_timer.h"

/**
 * @brief Timer types for RSVP.
 * @details Identifies the purpose of the timer.
 */
typedef enum {
    RSVP_TIMER_REFRESH, /**< Timer to send periodic refresh messages */
    RSVP_TIMER_CLEANUP, /**< Timer to expire state if no refresh is received */
} rsvp_timer_type_t;

/**
 * @brief Callback function for timer expiration.
 * @param [in] arg User-provided argument passed during timer creation.
 */
typedef void (*rsvp_timer_cb)(void* arg);

/**
 * @brief Embedded Timer Structure.
 * @details Holds the internal wheel timer node, callback information, and active state.
 */
typedef struct {
    timer_node_t node;      /**< Internal node for the wheel timer library */
    rsvp_timer_type_t type; /**< Type of the timer */
    rsvp_timer_cb cb;       /**< Callback executed on expiration */
    void* arg;              /**< Argument passed to the callback */
    bool active;            /**< True if the timer is currently running */
} rsvp_timer_t;

/**
 * @brief Initialize the timer management system.
 * @details Sets up the underlying wheel timer and communication pipes.
 */
void rsvp_timer_init(void);

/**
 * @brief Start a timer.
 * @details Adds the timer to the wheel for expiration after the specified timeout.
 * @param [in,out] timer Pointer to the timer structure.
 * @param [in] type Type of the RSVP timer.
 * @param [in] timeout_ms Timeout interval in milliseconds.
 * @param [in] cb Callback function to execute on timeout.
 * @param [in] arg Argument to pass to the callback.
 */
void rsvp_timer_start(rsvp_timer_t* timer, rsvp_timer_type_t type, uint32_t timeout_ms, rsvp_timer_cb cb, void* arg);

/**
 * @brief Stop a timer.
 * @details Removes the timer from the wheel if it is active.
 * @param [in,out] timer Pointer to the timer structure to stop.
 */
void rsvp_timer_stop(rsvp_timer_t* timer);

/**
 * @brief Reset/Restart an existing timer.
 * @details Modifies an active timer to expire after the new timeout interval.
 * @param [in,out] timer Pointer to the timer structure.
 * @param [in] timeout_ms The new timeout interval in milliseconds.
 * @return true if successful, false otherwise.
 */
bool rsvp_timer_reset(rsvp_timer_t* timer, uint32_t timeout_ms);

/**
 * @brief Get all active timer file descriptors for polling.
 * @details Retrieves the read-side of the timer pipe used to signal expirations.
 * @param [out] fds Array to populate with file descriptors.
 * @param [in] max_fds Maximum number of descriptors the array can hold.
 * @return The number of fds added to the array.
 */
int rsvp_timer_get_fds(int* fds, int max_fds);

/**
 * @brief Handle a timer expiration for a given fd.
 * @details Reads expired timer pointers from the pipe and executes their callbacks.
 * @param [in] fd The file descriptor that triggered the event.
 */
void rsvp_timer_handle_exp(int fd);

#endif /* RSVP_TIMERS_H */