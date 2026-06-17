/**
 * @file hal_timer.h
 * @brief Hardware Abstraction Layer for Timer.
 * @details Provides an interface for the platform-specific timer subsystem.
 */

#ifndef HAL_TIMER_H
#define HAL_TIMER_H

#include <stdint.h>

/**
 * @brief Initialize the hardware/platform timer subsystem.
 * @details Sets up the underlying timer mechanism (e.g., timerfd on Linux).
 * @return A file descriptor for polling, or -1 on error.
 */
int hal_timer_init(void);

/**
 * @brief Set the next expiration time for the central timer.
 * @details Arms the timer to trigger after a specific delay.
 * @param [in] timeout_ms The timeout duration in milliseconds relative to now.
 */
void hal_timer_set(uint32_t timeout_ms);

/**
 * @brief Clear the central timer.
 * @details Disarms the timer so it will not trigger.
 */
void hal_timer_clear(void);

#endif /* HAL_TIMER_H */
