/**
 * @file rsvp_log.c
 * @brief Implementation of the RSVP-TE logging mechanism.
 * @details This file implements the logging functions defined in rsvp_log.h.
 */

#include "common/rsvp_log.h"

#ifdef RSVP_LOGGING_ENABLED

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static rsvp_log_level_t current_level = LOG_LEVEL_DEBUG;
static FILE* log_fp = NULL;

void rsvp_log_init(const char* log_file) {
    if (log_file) {
        /* Open the specified log file in append mode */
        log_fp = fopen(log_file, "a");
        if (!log_fp) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file);
        }
    }
}

void rsvp_log_close(void) {
    if (log_fp) {
        /* Close the active log file and reset the file pointer */
        fclose(log_fp);
        log_fp = NULL;
    }
}

void rsvp_set_log_level(rsvp_log_level_t level) { 
    current_level = level; 
}

void rsvp_log(rsvp_log_level_t level, const char* func, int line,
              const char* format, ...) {
    /* Discard messages that are below the current logging threshold */
    if (level < current_level) {
        return;
    }

    FILE* out = log_fp ? log_fp : stdout;

    /* Map the log level enumeration to its string representation */
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

    /* Optimization: only get time if needed or every N calls, but for simplicity
     * let's just use a faster way if possible. For now, keep strftime but remove fflush.
     */
    static time_t last_t = 0;
    static char time_buf[26] = {0};
    time_t now = time(NULL);

    if (now != last_t) {
        struct tm tm_info;
        localtime_r(&now, &tm_info);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
        last_t = now;
    }

    /* Print the log prefix containing timestamp, level, function name, and line number */
    fprintf(out, "[%s] [%s] %s:%d: ", time_buf, level_str, func, line);

    /* Process the variadic arguments and format the main log message */
    va_list args;
    va_start(args, format);
    vfprintf(out, format, args);
    va_end(args);

    fprintf(out, "\n");

    /* Only flush for errors to avoid slowing down the main path */
    if (level >= LOG_LEVEL_WARN) {
        fflush(out);
    }

    /* Also print errors to stderr for immediate feedback if not already logging to stdout/stderr */
    if (level == LOG_LEVEL_ERROR && out != stderr) {
        fprintf(stderr, "[%s] [%s] %s:%d: ", time_buf, level_str, func, line);
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        fprintf(stderr, "\n");
        fflush(stderr);
    }
}

#endif /* RSVP_LOGGING_ENABLED */
