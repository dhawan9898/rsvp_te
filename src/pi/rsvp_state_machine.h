/**
 * @file rsvp_state_machine.h
 * @brief RSVP State Machine and Message Handling.
 * @details Core logic for processing RSVP messages, managing path and reservation state, and propagating protocol events.
 */

#ifndef RSVP_STATE_MACHINE_H
#define RSVP_STATE_MACHINE_H

#include "rsvp_parser.h"

/**
 * @brief Handle a parsed RSVP message.
 * @details Demultiplexes the message by type (Path, Resv, PathErr, etc.) and invokes the corresponding state machine logic.
 * @param [in] info Pointer to the parsed message information.
 */
void rsvp_handle_message(struct rsvp_message_info* info);

/**
 * @brief Initiate a new PATH message for an LSP.
 * @details Creates a new Path State Block (PSB) at the ingress node and triggers the first Path message downstream.
 * @param [in] src The source (ingress) IPv4 address.
 * @param [in] dest The destination (egress) IPv4 address.
 * @param [in] tunnel_id The unique tunnel identifier.
 * @param [in] lsp_name Optional name for the LSP.
 */
void rsvp_initiate_path(struct in_addr* src, struct in_addr* dest,
                        uint16_t tunnel_id, const char* lsp_name);

/**
 * @brief Teardown an existing LSP by Tunnel ID.
 * @details Finds the corresponding PSB and initiates a PathTear message to gracefully remove state downstream.
 * @param [in] tunnel_id The tunnel identifier of the LSP to teardown.
 */
void rsvp_teardown_path(uint16_t tunnel_id);

#endif /* RSVP_STATE_MACHINE_H */
