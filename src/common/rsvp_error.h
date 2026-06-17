/**
 * @file rsvp_error.h
 * @brief RSVP-TE error code definitions.
 * @details Contains the enumeration of possible error codes returned by RSVP-TE functions.
 */

#ifndef RSVP_ERROR_H
#define RSVP_ERROR_H

/**
 * @brief RSVP error codes.
 * @details Enumeration of possible error codes returned by RSVP-TE functions.
 */
typedef enum {
    RSVP_SUCCESS = 0,               /**< Operation completed successfully. */
    RSVP_ERR_MALFORMED_OBJ = -1,    /**< A malformed object was encountered. */
    RSVP_ERR_MEM_ALLOC = -2,        /**< Memory allocation failed. */
    RSVP_ERR_INVALID_PARAM = -3,    /**< Invalid parameter was passed to a function. */
    RSVP_ERR_NOT_FOUND = -4,        /**< The requested item was not found. */
    RSVP_ERR_TIMEOUT = -5,          /**< An operation timed out. */
    RSVP_ERR_SYS = -6,              /**< A system error occurred. */
    RSVP_ERR_BUFFER_TOO_SMALL = -7, /**< The provided buffer was too small. */
    RSVP_ERR_CHECKSUM = -8,         /**< A checksum validation failed. */
    RSVP_ERR_SEND_FAILED = -9       /**< Packet transmission failed. */
} rsvp_error_t;

#endif /* RSVP_ERROR_H */
