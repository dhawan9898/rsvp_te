#ifndef HAL_TIMER_H
#define HAL_TIMER_H

#include <stdint.h>

/**
 * HAL callback for when a platform timer expires.
 */
typedef void (*hal_timer_cb)(void *data);

/**
 * Platform-dependent timer functions to be implemented by the PD layer.
 */
uint32_t hal_timer_add(uint32_t timeout_ms, hal_timer_cb cb, void *data);
void     hal_timer_remove(uint32_t hal_timer_id);

#endif /* HAL_TIMER_H */
