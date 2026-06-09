#include "hal/hal_timer.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <errno.h>

/**
 * Linux implementation of HAL timer using timerfd.
 */

uint32_t hal_timer_add(uint32_t timeout_ms, hal_timer_cb cb, void *data) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (tfd < 0) {
        perror("timerfd_create");
        return 0;
    }

    struct itimerspec new_value;
    new_value.it_value.tv_sec = timeout_ms / 1000;
    new_value.it_value.tv_nsec = (timeout_ms % 1000) * 1000000;
    new_value.it_interval.tv_sec = 0; /* One-shot by default in RSVP SM */
    new_value.it_interval.tv_nsec = 0;

    if (timerfd_settime(tfd, 0, &new_value, NULL) < 0) {
        perror("timerfd_settime");
        close(tfd);
        return 0;
    }

    /* In a real implementation, we'd add tfd to our poll() loop.
     * For now, we return the fd as the timer id. */
    printf("[HAL-Linux] Created timerfd %d for %u ms\n", tfd, timeout_ms);
    return (uint32_t)tfd;
}

void hal_timer_remove(uint32_t hal_timer_id) {
    if (hal_timer_id > 0) {
        printf("[HAL-Linux] Removing timerfd %d\n", hal_timer_id);
        close((int)hal_timer_id);
    }
}
