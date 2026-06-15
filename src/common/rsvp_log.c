#include "common/rsvp_log.h"

#ifdef RSVP_LOGGING_ENABLED

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static rsvp_log_level_t current_level = LOG_LEVEL_DEBUG;
static FILE* log_fp = NULL;

void rsvp_log_init(const char* log_file) {
    if (log_file) {
        log_fp = fopen(log_file, "a");
        if (!log_fp) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file);
        }
    }
}

void rsvp_log_close(void) {
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

void rsvp_set_log_level(rsvp_log_level_t level) { current_level = level; }

void rsvp_log(rsvp_log_level_t level, const char* func, int line,
              const char* format, ...) {
    if (level < current_level) {
        return;
    }

    FILE* out = log_fp ? log_fp : stdout;

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

    fprintf(out, "[%s] [%s] %s:%d: ", time_buf, level_str, func, line);

    va_list args;
    va_start(args, format);
    vfprintf(out, format, args);
    va_end(args);

    fprintf(out, "\n");
    fflush(out);

    /* Also print errors to stderr for immediate feedback */
    if (level == LOG_LEVEL_ERROR && out != stderr) {
        fprintf(stderr, "[%s] [%s] %s:%d: ", time_buf, level_str, func, line);
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        fprintf(stderr, "\n");
    }
}

#endif /* RSVP_LOGGING_ENABLED */
