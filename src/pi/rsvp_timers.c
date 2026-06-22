/**
 * @file rsvp_timers.c
 * @brief RSVP Timer Management Implementation.
 * @details Uses a wheel timer library and a pipe to integrate asynchronous timer expirations into the main poll loop.
 */

#include "rsvp_timers.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/rsvp_log.h"

static timer_wheel_t* global_wheel = NULL;
static int timer_pipe[2] = {-1, -1};

#define MAX_ACTIVE_TIMERS 2048
struct active_timer_entry {
    rsvp_timer_t* timer;
    uint64_t seq;
};
static struct active_timer_entry active_timers[MAX_ACTIVE_TIMERS];
static uint64_t global_timer_seq = 1;

struct timer_exp_msg {
    rsvp_timer_t* timer;
    uint64_t seq;
};

static void register_active_timer(rsvp_timer_t* timer, uint64_t seq) {
    for (int i = 0; i < MAX_ACTIVE_TIMERS; i++) {
        if (active_timers[i].timer == NULL) {
            active_timers[i].timer = timer;
            active_timers[i].seq = seq;
            return;
        }
    }
    LOG_ERROR("Active timers registry full!");
}

static void unregister_active_timer(rsvp_timer_t* timer) {
    for (int i = 0; i < MAX_ACTIVE_TIMERS; i++) {
        if (active_timers[i].timer == timer) {
            active_timers[i].timer = NULL;
            active_timers[i].seq = 0;
            return;
        }
    }
}

static bool is_timer_active_and_matches(rsvp_timer_t* timer, uint64_t seq) {
    for (int i = 0; i < MAX_ACTIVE_TIMERS; i++) {
        if (active_timers[i].timer == timer) {
            return active_timers[i].seq == seq;
        }
    }
    return false;
}

/**
 * @brief Internal callback executed by the wheel timer thread.
 * @details Marks the timer as inactive and writes expiration message into the communication pipe.
 * @param [in] arg Pointer to the rsvp_timer_t structure.
 */
static void internal_wheel_cb(void* arg) {
    rsvp_timer_t* timer = (rsvp_timer_t*)arg;
    atomic_store(&timer->active, false);
    
    struct timer_exp_msg msg;
    msg.timer = timer;
    msg.seq = timer->seq;

    /* Write to pipe so it is processed in the main thread event loop */
    if (write(timer_pipe[1], &msg, sizeof(msg)) != sizeof(msg)) {
        LOG_ERROR("Failed to write to timer pipe: %s", strerror(errno));
    }
}

void rsvp_timer_init(void) {
    memset(active_timers, 0, sizeof(active_timers));

    /* Create an unnamed pipe for IPC between timer threads and the main loop */
    if (pipe(timer_pipe) < 0) {
        LOG_ERROR("Failed to create timer pipe: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    /* Make the read side non-blocking to prevent the main loop from stalling */
    int flags = fcntl(timer_pipe[0], F_GETFL, 0);
    fcntl(timer_pipe[0], F_SETFL, flags | O_NONBLOCK);

    /* Initialize wheel timer: 10ms resolution, 2 worker threads */
    global_wheel = timer_wheel_create(10, 2);
    if (!global_wheel) {
        LOG_ERROR("Failed to initialize wheel timer");
        exit(EXIT_FAILURE);
    }

    LOG_INFO("RSVP Timer system initialized with wheel_timer");
}

void rsvp_timer_start(rsvp_timer_t* timer, rsvp_timer_type_t type, uint32_t timeout_ms, rsvp_timer_cb cb, void* arg) {
    if (!timer || !global_wheel) return;
    
    /* Ensure the timer is stopped before re-starting to avoid corrupting the wheel lists */
    if (atomic_load(&timer->active)) {
        rsvp_timer_stop(timer);
    }

    timer_node_init(&timer->node);
    timer->type = type;
    timer->cb = cb;
    timer->arg = arg;
    atomic_store(&timer->active, true);
    
    timer->seq = ++global_timer_seq;
    register_active_timer(timer, timer->seq);
    
    if (timer_add(global_wheel, &timer->node, timeout_ms, internal_wheel_cb, timer) < 0) {
        LOG_ERROR("Failed to add timer to wheel");
        atomic_store(&timer->active, false);
        unregister_active_timer(timer);
    }
}

void rsvp_timer_stop(rsvp_timer_t* timer) {
    if (!timer || !global_wheel || !atomic_load(&timer->active)) return;
    
    timer_del(global_wheel, &timer->node);
    atomic_store(&timer->active, false);
    unregister_active_timer(timer);
}

bool rsvp_timer_reset(rsvp_timer_t* timer, uint32_t timeout_ms) {
    if (!timer || !global_wheel || !atomic_load(&timer->active)) return false;
    
    if (timer_mod(global_wheel, &timer->node, timeout_ms) == 0) {
        return true;
    }
    return false;
}

int rsvp_timer_get_fds(int* fds, int max_fds) {
    if (timer_pipe[0] >= 0 && max_fds > 0) {
        fds[0] = timer_pipe[0];
        return 1;
    }
    return 0;
}

void rsvp_timer_handle_exp(int fd) {
    if (fd != timer_pipe[0]) return;

    struct timer_exp_msg msg;
    /* Read all expired timer pointers from the pipe and execute their user callbacks */
    while (read(fd, &msg, sizeof(msg)) == sizeof(msg)) {
        if (is_timer_active_and_matches(msg.timer, msg.seq)) {
            unregister_active_timer(msg.timer);
            if (msg.timer->cb) {
                msg.timer->cb(msg.timer->arg);
            }
        } else {
            LOG_DEBUG("Timer expiration ignored (stale/deleted timer: %p, seq: %llu)", 
                      msg.timer, (unsigned long long)msg.seq);
        }
    }
}