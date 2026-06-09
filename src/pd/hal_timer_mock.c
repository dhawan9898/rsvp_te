#include "hal/hal_timer.h"
#include <stdio.h>

/**
 * Mock implementation of HAL timer for building purposes.
 * This will be replaced by a real PD implementation (e.g., using libevent or timerfd).
 */

static uint32_t next_timer_id = 1;

uint32_t hal_timer_add(uint32_t timeout_ms, hal_timer_cb cb, void *data) {
    (void)cb;
    (void)data;
    uint32_t id = next_timer_id++;
    printf("[HAL] Added timer %u with timeout %u ms\n", id, timeout_ms);
    return id;
}

void hal_timer_remove(uint32_t hal_timer_id) {
    printf("[HAL] Removed timer %u\n", hal_timer_id);
}
