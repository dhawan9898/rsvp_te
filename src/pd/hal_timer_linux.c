#include "hal/hal_timer.h"

#include <errno.h>
#include <string.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "common/rsvp_log.h"

static int central_tfd = -1;

int hal_timer_init(void) {
    central_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (central_tfd < 0) {
        LOG_ERROR("timerfd_create: %s", strerror(errno));
        return -1;
    }
    LOG_INFO("[HAL-Linux] Central timerfd initialized: %d", central_tfd);
    return central_tfd;
}

void hal_timer_set(uint32_t timeout_ms) {
    if (central_tfd < 0) return;

    struct itimerspec new_value;
    new_value.it_value.tv_sec = timeout_ms / 1000;
    new_value.it_value.tv_nsec = (timeout_ms % 1000) * 1000000;
    new_value.it_interval.tv_sec = 0;
    new_value.it_interval.tv_nsec = 0;

    if (timerfd_settime(central_tfd, 0, &new_value, NULL) < 0) {
        LOG_ERROR("timerfd_settime: %s", strerror(errno));
    }
}

void hal_timer_clear(void) {
    if (central_tfd < 0) return;

    struct itimerspec new_value;
    memset(&new_value, 0, sizeof(new_value));

    if (timerfd_settime(central_tfd, 0, &new_value, NULL) < 0) {
        LOG_ERROR("timerfd_settime clear: %s", strerror(errno));
    }
}
