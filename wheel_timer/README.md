# Hierarchical Wheel Timer

An industrial-grade, high-performance hierarchical wheel timer module implemented in C for Linux using POSIX threads.

## Features
- **Hierarchical Design**: 5-level cascading wheel (TVR + TV1-TV4) for $O(1)$ amortized insertion and efficient expiration.
- **High Capacity**: Supports up to $2^{32}$ ticks (e.g., ~49.7 days at 1ms resolution).
- **Thread-Safe**: Fully thread-safe API using pthreads.
- **Asynchronous Execution**: Expired timers are dispatched to a worker thread pool, ensuring that long-running or blocking callbacks do not stall the main timer wheel.
- **Robustness**: Handles corner cases like timers expiring in the current/past jiffy, re-adding timers from their own callbacks, and concurrent modification/deletion.

## Architecture
The timer wheel uses a classic cascading structure:
- **Root Wheel (TVR)**: 256 slots (8 bits).
- **Secondary Wheels (TV1-TV4)**: 64 slots each (6 bits each).
- **Tick Thread**: A dedicated thread that advances the wheel every `tick_ms` using `clock_nanosleep`.
- **Worker Pool**: A set of worker threads that pull from an internal dispatch queue to execute callbacks.

## API Usage

### Initialization
```c
timer_wheel_t *wheel = timer_wheel_create(10, 4); // 10ms resolution, 4 worker threads
```

### Adding a Timer
```c
timer_node_t my_timer = {0}; // Must be zero-initialized
timer_add(wheel, &my_timer, 1000, my_callback, (void*)42); // Expire in 1000ms
```

### Modifying a Timer
```c
timer_mod(wheel, &my_timer, 2000); // Reschedule to 2000ms from now
```

### Deleting a Timer
```c
timer_del(wheel, &my_timer); // Remove if pending
```

### Cleanup
```c
timer_wheel_destroy(wheel); // Stops all threads and cleans up
```

## Building and Testing
A `Makefile` is provided. To build and run the test suite:
```bash
make test
```

## Design Notes
- **Callback Safety**: Callbacks are executed in a separate thread pool. This prevents a single slow callback from delaying all other timers.
- **Precision**: Uses `CLOCK_MONOTONIC` to ensure immunity to system time changes (NTP jumps, leap seconds).
- **Memory Management**: The library does not allocate `timer_node_t` internally; the user provides the memory (either on stack, heap, or static). This avoids hidden allocations and fragmentation.

## License
MIT License.
