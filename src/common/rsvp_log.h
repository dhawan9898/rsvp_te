/**
 * @file rsvp_log.h
 * @brief RSVP-TE logging mechanism.
 * @details Provides macros and functions for logging across the RSVP-TE codebase.
 */

#ifndef RSVP_LOG_H
#define RSVP_LOG_H

#include <stdio.h>

/**
 * @brief Logging levels.
 * @details Defines the verbosity level of the logging mechanism.
 */
typedef enum {
    LOG_LEVEL_DEBUG = 0, /**< Debug level logging */
    LOG_LEVEL_INFO,      /**< Informational level logging */
    LOG_LEVEL_WARN,      /**< Warning level logging */
    LOG_LEVEL_ERROR      /**< Error level logging */
} rsvp_log_level_t;

#ifdef RSVP_LOGGING_ENABLED

/**
 * @brief Initialize the logging subsystem.
 * @details Opens the log file for writing if provided, or configures logging to standard output.
 * @param [in] log_file Path to the log file, or NULL for standard output.
 */
void rsvp_log_init(const char* log_file);

/**
 * @brief Close the logging subsystem.
 * @details Closes the log file if it was opened.
 */
void rsvp_log_close(void);

/**
 * @brief Set the minimum logging level.
 * @details Messages below this level will be discarded.
 * @param [in] level The minimum log level to display.
 */
void rsvp_set_log_level(rsvp_log_level_t level);

/**
 * @brief Log a message.
 * @details Logs a formatted message with a specific log level, including file name, function name, and line number.
 * @param [in] level The log level of the message.
 * @param [in] func The name of the calling function.
 * @param [in] line The line number where the log was called.
 * @param [in] format The format string for the message.
 * @param [in] ... Additional arguments for the format string.
 */
void rsvp_log(rsvp_log_level_t level, const char* func, int line,
              const char* format, ...);

/** @brief Macro for debug logging */
#define LOG_DEBUG(fmt, ...) \
    rsvp_log(LOG_LEVEL_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)
/** @brief Macro for info logging */
#define LOG_INFO(fmt, ...) \
    rsvp_log(LOG_LEVEL_INFO, __func__, __LINE__, fmt, ##__VA_ARGS__)
/** @brief Macro for warning logging */
#define LOG_WARN(fmt, ...) \
    rsvp_log(LOG_LEVEL_WARN, __func__, __LINE__, fmt, ##__VA_ARGS__)
/** @brief Macro for error logging */
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
