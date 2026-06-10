#include "rsvp_timers.h"
#include "hal/hal_timer.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_TIMERS 100

struct rsvp_timer_entry {
    uint32_t          id;
    rsvp_timer_type_t type;
    rsvp_timer_cb     cb;
    void             *arg;
    int               fd;
    bool              active;
};

static struct rsvp_timer_entry timers[MAX_TIMERS];

void rsvp_timer_init(void) {
    for (int i = 0; i < MAX_TIMERS; i++) {
        timers[i].active = false;
    }
    printf("RSVP Timer system initialized\n");
}

uint32_t rsvp_timer_start(rsvp_timer_type_t type, uint32_t timeout_ms, rsvp_timer_cb cb, void *arg) {
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!timers[i].active) {
            timers[i].fd = (int)hal_timer_add(timeout_ms, NULL, NULL);
            if (timers[i].fd <= 0) return 0;

            timers[i].id = (uint32_t)timers[i].fd;
            timers[i].type = type;
            timers[i].cb = cb;
            timers[i].arg = arg;
            timers[i].active = true;
            return timers[i].id;
        }
    }
    return 0;
}

void rsvp_timer_stop(uint32_t timer_id) {
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (timers[i].active && timers[i].id == timer_id) {
            hal_timer_remove(timer_id);
            timers[i].active = false;
            return;
        }
    }
}

void rsvp_timer_reset(uint32_t timer_id, uint32_t timeout_ms) {
    (void)timer_id;
    (void)timeout_ms;
    /* In a full implementation, we'd update the timerfd here */
}

int rsvp_timer_get_fds(int *fds, int max_fds) {
    int count = 0;
    for (int i = 0; i < MAX_TIMERS && count < max_fds; i++) {
        if (timers[i].active) {
            fds[count++] = timers[i].fd;
        }
    }
    return count;
}

void rsvp_timer_handle_exp(int fd) {
    uint64_t exp;
    ssize_t rc = read(fd, &exp, sizeof(exp));
    if (rc != sizeof(exp)) {
        if (rc < 0) {
            perror("rsvp_timer_handle_exp: read");
        } else {
            fprintf(stderr, "rsvp_timer_handle_exp: short read %zd\n", rc);
        }
    }

    for (int i = 0; i < MAX_TIMERS; i++) {
        if (timers[i].active && timers[i].fd == fd) {
            if (timers[i].cb) {
                timers[i].cb(timers[i].arg);
            }
            /* One-shot logic: stop the timer after execution */
            rsvp_timer_stop(timers[i].id);
            return;
        }
    }
}
