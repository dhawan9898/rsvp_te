#ifndef HAL_TIMER_H
#define HAL_TIMER_H

#include <stdint.h>

/**
 * Initialize the hardware/platform timer subsystem.
 * Returns a file descriptor for polling, or -1 on error.
 */
int hal_timer_init(void);

/**
 * Set the next expiration time for the central timer.
 * timeout_ms is relative to now.
 */
void hal_timer_set(uint32_t timeout_ms);

/**
 * Clear the central timer.
 */
void hal_timer_clear(void);

#endif /* HAL_TIMER_H */
