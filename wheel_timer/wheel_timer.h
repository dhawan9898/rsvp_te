#ifndef WHEEL_TIMER_H
#define WHEEL_TIMER_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WHEEL_TVR_BITS 8
#define WHEEL_TVN_BITS 6
#define WHEEL_TVR_SIZE (1 << WHEEL_TVR_BITS)
#define WHEEL_TVN_SIZE (1 << WHEEL_TVN_BITS)
#define WHEEL_TVR_MASK (WHEEL_TVR_SIZE - 1)
#define WHEEL_TVN_MASK (WHEEL_TVN_SIZE - 1)

typedef void (*timer_cb_t)(void* arg);

/* Opaque handle for the timer wheel */
typedef struct timer_wheel timer_wheel_t;

typedef struct timer_node_s {
    struct list_head entry;
    uint64_t expires; /* Absolute tick value when this timer expires */
    uint64_t period;  /* Period in ticks for periodic timers, 0 if one-shot */
    timer_cb_t callback;
    void* arg;
    timer_wheel_t* wheel;  /* Wheel this node is currently registered with */
    bool pending;          /* Flag to track if timer is in a wheel */
    atomic_bool executing; /* Flag to track if callback is currently running */
} timer_node_t;

/**
 * timer_node_init - Initialize a timer node
 * @node: The node to initialize
 */
void timer_node_init(timer_node_t* node);

/**
 * timer_wheel_create - Initialize the timer wheel
 * @tick_ms: Tick resolution in milliseconds (e.g., 1 or 10)
 * @worker_count: Number of threads in the callback worker pool
 *
 * Returns a pointer to the initialized wheel, or NULL on failure.
 */
timer_wheel_t* timer_wheel_create(unsigned int tick_ms, int worker_count);

/**
 * timer_wheel_destroy - Stop and cleanup the timer wheel
 * @wheel: The wheel to destroy
 */
void timer_wheel_destroy(timer_wheel_t* wheel);

/**
 * timer_add - Add a new one-shot timer
 * @wheel: The wheel to add to
 * @node: The timer node to add
 * @expires_ms: Delay from now in milliseconds
 * @cb: Callback function
 * @arg: Argument for callback
 *
 * Returns 0 on success, negative on error.
 */
int timer_add(timer_wheel_t* wheel, timer_node_t* node, unsigned int expires_ms,
              timer_cb_t cb, void* arg);

/**
 * timer_add_periodic - Add a periodic timer
 * @wheel: The wheel to add to
 * @node: The timer node to add
 * @period_ms: Interval between executions in milliseconds
 * @cb: Callback function
 * @arg: Argument for callback
 *
 * Returns 0 on success, negative on error.
 */
int timer_add_periodic(timer_wheel_t* wheel, timer_node_t* node,
                       unsigned int period_ms, timer_cb_t cb, void* arg);

/**
 * timer_del - Delete a pending timer (Asynchronous)
 * @wheel: The wheel the timer belongs to
 * @node: The timer node to delete
 *
 * Returns 0 if timer was deleted or is currently executing,
 * 1 if it wasn't pending, negative on error.
 *
 * Note: If the timer is currently executing, it will not be re-armed,
 * but this function returns IMMEDIATELY without waiting for the callback.
 */
int timer_del(timer_wheel_t* wheel, timer_node_t* node);

/**
 * timer_del_sync - Delete a pending timer and wait for completion
 * @wheel: The wheel
 * @node: The timer node
 *
 * Similar to timer_del, but if the timer is currently executing,
 * this function blocks until the callback has finished.
 *
 * WARNING: Do NOT call this from within the timer's own callback.
 */
int timer_del_sync(timer_wheel_t* wheel, timer_node_t* node);

/**
 * timer_mod - Modify an existing timer's expiration
 * @wheel: The wheel
 * @node: The timer node
 * @expires_ms: New delay from now in milliseconds
 *
 * Returns 0 on success.
 */
int timer_mod(timer_wheel_t* wheel, timer_node_t* node,
              unsigned int expires_ms);

#ifdef __cplusplus
}
#endif

#endif /* WHEEL_TIMER_H */
