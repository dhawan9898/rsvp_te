#ifndef RSVP_STATE_MACHINE_H
#define RSVP_STATE_MACHINE_H

#include "rsvp_parser.h"

/**
 * Handle a parsed RSVP message.
 */
void rsvp_handle_message(struct rsvp_message_info* info);

/**
 * Initiate a new PATH message for an LSP.
 */
void rsvp_initiate_path(struct in_addr* src, struct in_addr* dest,
                        uint16_t tunnel_id, char* lsp_name);

#endif /* RSVP_STATE_MACHINE_H */
