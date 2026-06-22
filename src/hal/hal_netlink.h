/**
 * @file hal_netlink.h
 * @brief Hardware Abstraction Layer for Netlink.
 * @details Provides an interface for Netlink socket operations, including interface/address monitoring, routing, and MPLS label management.
 */

#ifndef HAL_NETLINK_H
#define HAL_NETLINK_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Initialize Netlink socket for interface/address monitoring.
 * @details Opens a netlink socket and binds it to receive link and address events.
 * @return 0 on success, or -1 on error.
 */
int hal_netlink_init(void);

/**
 * @brief Get the file descriptor for the Netlink socket.
 * @details Used for polling the socket for incoming events.
 * @return The file descriptor of the netlink socket.
 */
int hal_netlink_get_fd(void);

/**
 * @brief Process a message from the Netlink socket.
 * @details Reads available data from the netlink socket and processes link, address, and route updates.
 */
void hal_netlink_process(void);

/**
 * @brief Get the local address for a given interface index.
 * @details Retrieves the primary IPv4 address configured on the specified interface.
 * @param [in] ifindex The interface index to query.
 * @param [out] addr Pointer to an in_addr structure where the result will be stored.
 * @return 0 on success, or -1 if the address could not be found.
 */
int hal_netlink_get_local_addr(int ifindex, struct in_addr* addr);

/**
 * @brief Get the egress interface for a given destination address (route lookup).
 * @details Queries the routing table to find the egress interface and next hop for a specific destination.
 * @param [in] dest The destination IPv4 address.
 * @param [out] next_hop Pointer to store the next hop IP address.
 * @return The interface index on success, or -1 on error.
 */
int hal_netlink_get_egress_if(struct in_addr* dest, struct in_addr* next_hop);

/**
 * @brief Check if the given address is a local interface address.
 * @details Determines whether an IP address belongs to any local interface.
 * @param [in] addr The IPv4 address to check.
 * @return true if the address is local, false otherwise.
 */
bool hal_netlink_is_local_addr(struct in_addr* addr);

/**
 * @brief Install an MPLS label (swap or push) in the data plane.
 * @details Configures an MPLS route in the kernel data plane.
 * @param [in] in_label The incoming MPLS label (0 for ingress).
 * @param [out_label] The outgoing MPLS label.
 * @param [out_ifindex] The egress interface index.
 * @param [next_hop] The next hop IP address.
 * @param [dest_addr] The destination IP address (required for ingress).
 * @return 0 on success, or -1 on error.
 */
int hal_mpls_install(uint32_t in_label, uint32_t out_label, int out_ifindex,
                     struct in_addr* next_hop, struct in_addr* dest_addr);

/**
 * @brief Remove an MPLS label from the data plane.
 * @details Deletes an MPLS route from the kernel data plane.
 * @param [in] in_label The incoming MPLS label to remove (0 for ingress).
 * @param [in] dest_addr The destination IP address (required for ingress).
 * @return 0 on success, or -1 on error.
 */
int hal_mpls_remove(uint32_t in_label, struct in_addr* dest_addr);

/**
 * @brief Dump current MPLS routes to stdout.
 * @details Queries the kernel for all MPLS routes and prints them to standard output.
 */
void hal_mpls_dump(void);

#endif /* HAL_NETLINK_H */
