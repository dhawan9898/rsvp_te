/**
 * @file rsvp_dispatcher.h
 * @brief RSVP message dispatcher.
 * @details Responsible for initializing network sockets, running the main event loop, and transmitting raw RSVP packets.
 */

#ifndef RSVP_DISPATCHER_H
#define RSVP_DISPATCHER_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "common/rsvp_error.h"

/**
 * @brief Initialize the RSVP message dispatcher.
 * @details Opens raw IP sockets, sets necessary socket options like IP_HDRINCL and IP_ROUTER_ALERT, and initializes netlink.
 * @return 0 on success, -1 on failure.
 */
int rsvp_dispatcher_init(void);

/**
 * @brief Run the dispatcher event loop.
 * @details Blocks and polls for incoming data on the raw RSVP socket, netlink socket, timer fds, and stdin for the CLI.
 */
void rsvp_dispatcher_run(void);

/**
 * @brief Send an RSVP packet to a specific destination.
 * @details Constructs the IP header and sends the raw packet out the RSVP socket.
 * @param [in] src The source IPv4 address.
 * @param [in] dest The destination IPv4 address.
 * @param [in] buffer Pointer to the RSVP message buffer.
 * @param [in] len Length of the RSVP message.
 * @param [in] use_rao Set to true to include the IP Router Alert Option.
 * @return RSVP_SUCCESS on success, or an error code on failure.
 */
rsvp_error_t rsvp_send_packet(struct in_addr* src, struct in_addr* dest, uint8_t* buffer,
                     size_t len, bool use_rao);

#endif /* RSVP_DISPATCHER_H */
