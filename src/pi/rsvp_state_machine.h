#ifndef RSVP_STATE_MACHINE_H
#define RSVP_STATE_MACHINE_H

#include "rsvp_parser.h"

/**
 * Handle a parsed RSVP message.
 */
void rsvp_handle_message(struct rsvp_message_info *info);

/**
 * Manually initiate a PATH message (Ingress role).
 */
void rsvp_initiate_path(struct in_addr *dest, uint16_t tunnel_id, struct in_addr *next_hop);

#endif /* RSVP_STATE_MACHINE_H */
