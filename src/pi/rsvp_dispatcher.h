#ifndef RSVP_DISPATCHER_H
#define RSVP_DISPATCHER_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/**
 * Initialize the RSVP message dispatcher (e.g., open sockets).
 * Returns 0 on success, -1 on failure.
 */
int rsvp_dispatcher_init(void);

/**
 * Run the dispatcher event loop.
 */
void rsvp_dispatcher_run(void);

/**
 * Send an RSVP packet to a specific destination.
 */
int rsvp_send_packet(struct in_addr *dest, uint8_t *buffer, size_t len);

#endif /* RSVP_DISPATCHER_H */
