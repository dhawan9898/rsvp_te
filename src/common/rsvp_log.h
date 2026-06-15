#ifndef RSVP_LOG_H
#define RSVP_LOG_H

#include <stdio.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} rsvp_log_level_t;

#ifdef RSVP_LOGGING_ENABLED

void rsvp_log_init(const char* log_file);
void rsvp_log_close(void);
void rsvp_set_log_level(rsvp_log_level_t level);
void rsvp_log(rsvp_log_level_t level, const char* func, int line,
              const char* format, ...);

#define LOG_DEBUG(fmt, ...) \
    rsvp_log(LOG_LEVEL_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) \
    rsvp_log(LOG_LEVEL_INFO, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) \
    rsvp_log(LOG_LEVEL_WARN, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) \
    rsvp_log(LOG_LEVEL_ERROR, __func__, __LINE__, fmt, ##__VA_ARGS__)

#else

#define rsvp_log_init(log_file) ((void)0)
#define rsvp_log_close() ((void)0)
#define rsvp_set_log_level(level) ((void)0)
#define LOG_DEBUG(fmt, ...) ((void)0)
#define LOG_INFO(fmt, ...) ((void)0)
#define LOG_WARN(fmt, ...) ((void)0)
#define LOG_ERROR(fmt, ...) ((void)0)

#endif /* RSVP_LOGGING_ENABLED */

#endif /* RSVP_LOG_H */
