#include "rsvp_timers.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common/rsvp_log.h"
#include "hal/hal_timer.h"

#define MAX_TIMERS 100

struct rsvp_timer_entry {
    uint32_t id;
    rsvp_timer_type_t type;
    rsvp_timer_cb cb;
    void* arg;
    uint64_t expire_time_ms;
    bool active;
};

static struct rsvp_timer_entry timers[MAX_TIMERS];
static int central_fd = -1;
static uint32_t next_timer_id = 1;

static uint64_t get_current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void update_central_timer(void) {
    uint64_t now = get_current_time_ms();
    uint64_t min_expire = UINT64_MAX;
    bool active_timers = false;

    for (int i = 0; i < MAX_TIMERS; i++) {
        if (timers[i].active) {
            active_timers = true;
            if (timers[i].expire_time_ms < min_expire) {
                min_expire = timers[i].expire_time_ms;
            }
        }
    }

    if (!active_timers) {
        hal_timer_clear();
    } else {
        uint32_t diff = 0;
        if (min_expire > now) {
            diff = (uint32_t)(min_expire - now);
        }
        if (diff == 0) diff = 1; /* Fire immediately */
        hal_timer_set(diff);
    }
}

void rsvp_timer_init(void) {
    for (int i = 0; i < MAX_TIMERS; i++) {
        timers[i].active = false;
    }
    central_fd = hal_timer_init();
    LOG_INFO("RSVP Timer system initialized with central event loop");
}

uint32_t rsvp_timer_start(rsvp_timer_type_t type, uint32_t timeout_ms,
                          rsvp_timer_cb cb, void* arg) {
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!timers[i].active) {
            timers[i].id = next_timer_id++;
            if (next_timer_id == 0) next_timer_id = 1;
            timers[i].type = type;
            timers[i].cb = cb;
            timers[i].arg = arg;
            timers[i].expire_time_ms = get_current_time_ms() + timeout_ms;
            timers[i].active = true;
            
            update_central_timer();
            return timers[i].id;
        }
    }
    LOG_ERROR("Timer pool exhausted");
    return 0;
}

void rsvp_timer_stop(uint32_t timer_id) {
    if (timer_id == 0) return;
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (timers[i].active && timers[i].id == timer_id) {
            timers[i].active = false;
            update_central_timer();
            return;
        }
    }
}

bool rsvp_timer_reset(uint32_t timer_id, uint32_t timeout_ms) {
    if (timer_id == 0) return false;
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (timers[i].active && timers[i].id == timer_id) {
            timers[i].expire_time_ms = get_current_time_ms() + timeout_ms;
            update_central_timer();
            return true;
        }
    }
    return false;
}

int rsvp_timer_get_fds(int* fds, int max_fds) {
    if (central_fd >= 0 && max_fds > 0) {
        fds[0] = central_fd;
        return 1;
    }
    return 0;
}

void rsvp_timer_handle_exp(int fd) {
    if (fd != central_fd) return;

    uint64_t exp;
    ssize_t rc = read(fd, &exp, sizeof(exp));
    if (rc < 0 && errno != EAGAIN) {
        LOG_ERROR("rsvp_timer_handle_exp: read: %s", strerror(errno));
    }

    uint64_t now = get_current_time_ms();

    for (int i = 0; i < MAX_TIMERS; i++) {
        if (timers[i].active && timers[i].expire_time_ms <= now) {
            timers[i].active = false; /* Stop before calling to allow restart */
            if (timers[i].cb) {
                timers[i].cb(timers[i].arg);
            }
        }
    }
    
    update_central_timer();
}
