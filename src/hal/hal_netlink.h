#ifndef HAL_NETLINK_H
#define HAL_NETLINK_H

#include <stdint.h>
#include <netinet/in.h>

/**
 * Initialize Netlink socket for interface/address monitoring.
 */
int hal_netlink_init(void);

/**
 * Get the file descriptor for the Netlink socket.
 */
int hal_netlink_get_fd(void);

/**
 * Process a message from the Netlink socket.
 */
void hal_netlink_process(void);

/**
 * Get the local address for a given ifindex.
 */
int hal_netlink_get_local_addr(int ifindex, struct in_addr *addr);

/**
 * Get the ifindex for a given destination address (route lookup).
 */
int hal_netlink_get_egress_if(struct in_addr *dest, struct in_addr *next_hop);

#endif /* HAL_NETLINK_H */
