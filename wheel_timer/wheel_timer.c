#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "wheel_timer.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct timer_wheel {
    uint64_t jiffies;
    pthread_mutex_t lock;

    struct list_head tv1[WHEEL_TVR_SIZE];
    struct list_head tv2[WHEEL_TVN_SIZE];
    struct list_head tv3[WHEEL_TVN_SIZE];
    struct list_head tv4[WHEEL_TVN_SIZE];
    struct list_head tv5[WHEEL_TVN_SIZE];

    unsigned int tick_ms;
    atomic_bool running;

    pthread_t tick_thread;
    bool tick_thread_created;

    struct list_head expired_list;
    pthread_mutex_t dispatch_lock;
    pthread_cond_t dispatch_cond;

    pthread_mutex_t
        wait_lock; /* Protects executing state changes for sync_del */
    pthread_cond_t wait_cond; /* Signaled when a callback finishes */

    int worker_count;
    pthread_t* workers;
    int workers_started;
};

struct worker_args {
    timer_wheel_t* wheel;
    int id;
};

void timer_node_init(timer_node_t* node) {
    if (!node) return;
    memset(node, 0, sizeof(*node));
    INIT_LIST_HEAD(&node->entry);
    atomic_init(&node->executing, false);
}

static void internal_add_timer(timer_wheel_t* wheel, timer_node_t* node) {
    uint64_t expires = node->expires;
    int64_t idx = (int64_t)(expires - wheel->jiffies);
    struct list_head* vec;

    if (idx <= 0) {
        /* If timer is expired or expires in the current jiffy,
         * schedule it for the next possible tick to avoid missing it. */
        vec = wheel->tv1 + ((wheel->jiffies + 1) & WHEEL_TVR_MASK);
    } else if (idx < (int64_t)WHEEL_TVR_SIZE) {
        int i = expires & WHEEL_TVR_MASK;
        vec = wheel->tv1 + i;
    } else if (idx < (int64_t)(1ULL << (WHEEL_TVR_BITS + WHEEL_TVN_BITS))) {
        int i = (expires >> WHEEL_TVR_BITS) & WHEEL_TVN_MASK;
        vec = wheel->tv2 + i;
    } else if (idx < (int64_t)(1ULL << (WHEEL_TVR_BITS + 2 * WHEEL_TVN_BITS))) {
        int i = (expires >> (WHEEL_TVR_BITS + WHEEL_TVN_BITS)) & WHEEL_TVN_MASK;
        vec = wheel->tv3 + i;
    } else if (idx < (int64_t)(1ULL << (WHEEL_TVR_BITS + 3 * WHEEL_TVN_BITS))) {
        int i =
            (expires >> (WHEEL_TVR_BITS + 2 * WHEEL_TVN_BITS)) & WHEEL_TVN_MASK;
        vec = wheel->tv4 + i;
    } else {
        int i =
            (expires >> (WHEEL_TVR_BITS + 3 * WHEEL_TVN_BITS)) & WHEEL_TVN_MASK;
        vec = wheel->tv5 + i;
    }

    list_add_tail(&node->entry, vec);
    node->pending = true;
}

static int cascade(timer_wheel_t* wheel, struct list_head* tv, int index) {
    struct list_head list;
    struct list_head *pos, *tmp;

    INIT_LIST_HEAD(&list);
    list_splice_init(tv + index, &list);

    list_for_each_safe(pos, tmp, &list) {
        timer_node_t* node = list_entry(pos, timer_node_t, entry);
        internal_add_timer(wheel, node);
    }

    return index;
}

static void* worker_thread_func(void* arg) {
    struct worker_args* wargs = (struct worker_args*)arg;
    timer_wheel_t* wheel = wargs->wheel;
    int id = wargs->id;
    free(wargs);

    char thread_name[16];
    snprintf(thread_name, sizeof(thread_name), "tw_worker_%d", id);
    pthread_setname_np(pthread_self(), thread_name);

    while (1) {
        struct list_head node_list;
        INIT_LIST_HEAD(&node_list);

        pthread_mutex_lock(&wheel->dispatch_lock);
        while (atomic_load(&wheel->running) &&
               list_empty(&wheel->expired_list)) {
            pthread_cond_wait(&wheel->dispatch_cond, &wheel->dispatch_lock);
        }

        if (!atomic_load(&wheel->running) && list_empty(&wheel->expired_list)) {
            pthread_mutex_unlock(&wheel->dispatch_lock);
            break;
        }

        list_splice_init(&wheel->expired_list, &node_list);
        pthread_mutex_unlock(&wheel->dispatch_lock);

        /* Execute callbacks */
        struct list_head *pos, *tmp;
        list_for_each_safe(pos, tmp, &node_list) {
            timer_node_t* node = list_entry(pos, timer_node_t, entry);

            pthread_mutex_lock(&wheel->wait_lock);
            atomic_store(&node->executing, true);
            pthread_mutex_unlock(&wheel->wait_lock);

            if (node->callback) {
                node->callback(node->arg);
            }

            pthread_mutex_lock(&wheel->wait_lock);
            atomic_store(&node->executing, false);
            pthread_cond_broadcast(&wheel->wait_cond);
            pthread_mutex_unlock(&wheel->wait_lock);

            pthread_mutex_lock(&wheel->lock);
            /* Re-add if periodic and not already re-armed or deleted by user */
            if (atomic_load(&wheel->running) && node->period > 0 &&
                !node->pending) {
                node->expires += node->period;
                internal_add_timer(wheel, node);
            } else if (node->period == 0 && !node->pending) {
                /* Clear wheel association for one-shots that aren't pending */
                node->wheel = NULL;
            }
            pthread_mutex_unlock(&wheel->lock);
        }
    }
    return NULL;
}

static void* tick_thread_func(void* arg) {
    timer_wheel_t* wheel = (timer_wheel_t*)arg;
    struct timespec ts;
    uint64_t next_tick_ns;
    struct timespec now;

    pthread_setname_np(pthread_self(), "tw_tick");

    clock_gettime(CLOCK_MONOTONIC, &now);
    next_tick_ns = (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;

    while (atomic_load(&wheel->running)) {
        next_tick_ns += (uint64_t)wheel->tick_ms * 1000000ULL;
        ts.tv_sec = next_tick_ns / 1000000000ULL;
        ts.tv_nsec = next_tick_ns % 1000000000ULL;

        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) !=
               0) {
            if (errno != EINTR) break;
            if (!atomic_load(&wheel->running)) goto out;
        }

        pthread_mutex_lock(&wheel->lock);
        uint64_t next_jiffies = wheel->jiffies + 1;
        int index = next_jiffies & WHEEL_TVR_MASK;

        wheel->jiffies = next_jiffies;

        /* Cascade if necessary */
        if (!index &&
            (!cascade(wheel, wheel->tv2,
                      (next_jiffies >> WHEEL_TVR_BITS) & WHEEL_TVN_MASK)) &&
            (!cascade(wheel, wheel->tv3,
                      (next_jiffies >> (WHEEL_TVR_BITS + WHEEL_TVN_BITS)) &
                          WHEEL_TVN_MASK)) &&
            (!cascade(wheel, wheel->tv4,
                      (next_jiffies >> (WHEEL_TVR_BITS + 2 * WHEEL_TVN_BITS)) &
                          WHEEL_TVN_MASK))) {
            cascade(wheel, wheel->tv5,
                    (next_jiffies >> (WHEEL_TVR_BITS + 3 * WHEEL_TVN_BITS)) &
                        WHEEL_TVN_MASK);
        }

        /* Process expired timers in current bucket */
        struct list_head* bucket = wheel->tv1 + index;
        if (!list_empty(bucket)) {
            struct list_head expired;
            INIT_LIST_HEAD(&expired);

            struct list_head *pos, *tmp;
            list_for_each_safe(pos, tmp, bucket) {
                timer_node_t* node = list_entry(pos, timer_node_t, entry);
                node->pending = false;
                list_move_tail(pos, &expired);
            }

            /* Dispatch to worker pool */
            pthread_mutex_lock(&wheel->dispatch_lock);
            list_splice_init(&expired, &wheel->expired_list);
            pthread_cond_broadcast(&wheel->dispatch_cond);
            pthread_mutex_unlock(&wheel->dispatch_lock);
        }

        pthread_mutex_unlock(&wheel->lock);
    }
out:
    return NULL;
}

timer_wheel_t* timer_wheel_create(unsigned int tick_ms, int worker_count) {
    if (tick_ms == 0 || worker_count <= 0) return NULL;

    timer_wheel_t* wheel = calloc(1, sizeof(timer_wheel_t));
    if (!wheel) return NULL;

    wheel->tick_ms = tick_ms;
    wheel->worker_count = worker_count;
    atomic_store(&wheel->running, true);

    if (pthread_mutex_init(&wheel->lock, NULL) != 0) goto err_free_wheel;
    if (pthread_mutex_init(&wheel->dispatch_lock, NULL) != 0)
        goto err_destroy_lock;
    if (pthread_mutex_init(&wheel->wait_lock, NULL) != 0)
        goto err_destroy_dispatch_lock;
    if (pthread_cond_init(&wheel->dispatch_cond, NULL) != 0)
        goto err_destroy_wait_lock;
    if (pthread_cond_init(&wheel->wait_cond, NULL) != 0)
        goto err_destroy_dispatch_cond;

    for (int i = 0; i < WHEEL_TVR_SIZE; i++) INIT_LIST_HEAD(&wheel->tv1[i]);
    for (int i = 0; i < WHEEL_TVN_SIZE; i++) {
        INIT_LIST_HEAD(&wheel->tv2[i]);
        INIT_LIST_HEAD(&wheel->tv3[i]);
        INIT_LIST_HEAD(&wheel->tv4[i]);
        INIT_LIST_HEAD(&wheel->tv5[i]);
    }
    INIT_LIST_HEAD(&wheel->expired_list);

    wheel->workers = calloc(worker_count, sizeof(pthread_t));
    if (!wheel->workers) goto err_destroy_wait_cond;

    for (int i = 0; i < worker_count; i++) {
        struct worker_args* wargs = malloc(sizeof(struct worker_args));
        if (!wargs) goto err_stop_workers;
        wargs->wheel = wheel;
        wargs->id = i;

        if (pthread_create(&wheel->workers[i], NULL, worker_thread_func,
                           wargs) != 0) {
            free(wargs);
            goto err_stop_workers;
        }
        wheel->workers_started++;
    }

    if (pthread_create(&wheel->tick_thread, NULL, tick_thread_func, wheel) !=
        0) {
        goto err_stop_workers;
    }
    wheel->tick_thread_created = true;

    return wheel;

err_stop_workers:
    timer_wheel_destroy(wheel);
    return NULL;

err_destroy_wait_cond:
    pthread_cond_destroy(&wheel->wait_cond);
err_destroy_dispatch_cond:
    pthread_cond_destroy(&wheel->dispatch_cond);
err_destroy_wait_lock:
    pthread_mutex_destroy(&wheel->wait_lock);
err_destroy_dispatch_lock:
    pthread_mutex_destroy(&wheel->dispatch_lock);
err_destroy_lock:
    pthread_mutex_destroy(&wheel->lock);
err_free_wheel:
    free(wheel);
    return NULL;
}

void timer_wheel_destroy(timer_wheel_t* wheel) {
    if (!wheel) return;

    atomic_store(&wheel->running, false);

    if (wheel->tick_thread_created) {
        pthread_join(wheel->tick_thread, NULL);
    }

    pthread_mutex_lock(&wheel->dispatch_lock);
    pthread_cond_broadcast(&wheel->dispatch_cond);
    pthread_mutex_unlock(&wheel->dispatch_lock);

    for (int i = 0; i < wheel->workers_started; i++) {
        pthread_join(wheel->workers[i], NULL);
    }

    if (wheel->workers) free(wheel->workers);
    pthread_mutex_destroy(&wheel->lock);
    pthread_mutex_destroy(&wheel->dispatch_lock);
    pthread_mutex_destroy(&wheel->wait_lock);
    pthread_cond_destroy(&wheel->dispatch_cond);
    pthread_cond_destroy(&wheel->wait_cond);

    free(wheel);
}

int timer_add(timer_wheel_t* wheel, timer_node_t* node, unsigned int expires_ms,
              timer_cb_t cb, void* arg) {
    if (!wheel || !node) return -EINVAL;

    pthread_mutex_lock(&wheel->lock);

    if (!atomic_load(&wheel->running)) {
        pthread_mutex_unlock(&wheel->lock);
        return -ESHUTDOWN;
    }

    if (node->wheel && node->wheel != wheel) {
        pthread_mutex_unlock(&wheel->lock);
        return -EEXIST; /* Node belongs to another wheel */
    }

    if (node->pending) {
        list_del(&node->entry);
        node->pending = false;
    }

    node->wheel = wheel;
    node->expires = wheel->jiffies + (expires_ms / wheel->tick_ms);
    if (expires_ms > 0 && (expires_ms % wheel->tick_ms) != 0) {
        node->expires++; /* Round up */
    }

    node->period = 0; /* One-shot */
    node->callback = cb;
    node->arg = arg;

    internal_add_timer(wheel, node);

    pthread_mutex_unlock(&wheel->lock);
    return 0;
}

int timer_add_periodic(timer_wheel_t* wheel, timer_node_t* node,
                       unsigned int period_ms, timer_cb_t cb, void* arg) {
    if (!wheel || !node || period_ms == 0) return -EINVAL;

    pthread_mutex_lock(&wheel->lock);

    if (!atomic_load(&wheel->running)) {
        pthread_mutex_unlock(&wheel->lock);
        return -ESHUTDOWN;
    }

    if (node->wheel && node->wheel != wheel) {
        pthread_mutex_unlock(&wheel->lock);
        return -EEXIST;
    }

    if (node->pending) {
        list_del(&node->entry);
        node->pending = false;
    }

    node->wheel = wheel;
    node->period = period_ms / wheel->tick_ms;
    if (node->period == 0) node->period = 1;

    node->expires = wheel->jiffies + node->period;
    node->callback = cb;
    node->arg = arg;

    internal_add_timer(wheel, node);

    pthread_mutex_unlock(&wheel->lock);
    return 0;
}

int timer_del(timer_wheel_t* wheel, timer_node_t* node) {
    if (!wheel || !node) return -EINVAL;

    pthread_mutex_lock(&wheel->lock);
    int ret = 1;

    if (node->wheel && node->wheel != wheel) {
        pthread_mutex_unlock(&wheel->lock);
        return -EINVAL;
    }

    /* If it's periodic, stop it from re-arming */
    node->period = 0;

    if (node->pending) {
        list_del(&node->entry);
        node->pending = false;
        node->wheel = NULL;
        ret = 0;
    } else if (atomic_load(&node->executing)) {
        /* It's currently running, we've cleared period so it won't re-arm.
         * The worker thread will clear node->wheel when done. */
        ret = 0;
    }

    pthread_mutex_unlock(&wheel->lock);
    return ret;
}

int timer_del_sync(timer_wheel_t* wheel, timer_node_t* node) {
    int ret = timer_del(wheel, node);
    if (ret < 0) return ret;

    /* Wait for execution to finish if it was running */
    pthread_mutex_lock(&wheel->wait_lock);
    while (atomic_load(&node->executing)) {
        pthread_cond_wait(&wheel->wait_cond, &wheel->wait_lock);
    }
    pthread_mutex_unlock(&wheel->wait_lock);

    return ret;
}

int timer_mod(timer_wheel_t* wheel, timer_node_t* node,
              unsigned int expires_ms) {
    if (!wheel || !node) return -EINVAL;

    pthread_mutex_lock(&wheel->lock);

    if (!atomic_load(&wheel->running)) {
        pthread_mutex_unlock(&wheel->lock);
        return -ESHUTDOWN;
    }

    if (node->wheel && node->wheel != wheel) {
        pthread_mutex_unlock(&wheel->lock);
        return -EEXIST;
    }

    if (node->pending) {
        list_del(&node->entry);
    }

    node->wheel = wheel;
    node->expires = wheel->jiffies + (expires_ms / wheel->tick_ms);
    if (expires_ms > 0 && (expires_ms % wheel->tick_ms) != 0) {
        node->expires++;
    }

    internal_add_timer(wheel, node);
    pthread_mutex_unlock(&wheel->lock);
    return 0;
}
