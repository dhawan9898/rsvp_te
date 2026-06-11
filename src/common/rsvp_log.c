#include "common/rsvp_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static rsvp_log_level_t current_level = LOG_LEVEL_INFO;

void rsvp_set_log_level(rsvp_log_level_t level) { current_level = level; }

void rsvp_log(rsvp_log_level_t level, const char* func, int line,
              const char* format, ...) {
    if (level < current_level) {
        return;
    }

    const char* level_str = "UNKNOWN";
    switch (level) {
        case LOG_LEVEL_DEBUG:
            level_str = "DEBUG";
            break;
        case LOG_LEVEL_INFO:
            level_str = "INFO";
            break;
        case LOG_LEVEL_WARN:
            level_str = "WARN";
            break;
        case LOG_LEVEL_ERROR:
            level_str = "ERROR";
            break;
    }

    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    char time_buf[26];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("[%s] [%s] %s:%d: ", time_buf, level_str, func, line);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
}
