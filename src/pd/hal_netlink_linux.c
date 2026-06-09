#include "hal/hal_netlink.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#define MAX_INTERFACES 32

struct interface {
    int ifindex;
    struct in_addr addr;
    bool active;
};

static struct interface ifaces[MAX_INTERFACES];
static int nl_sock = -1;

int hal_netlink_init(void) {
    struct sockaddr_nl sa;

    nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_sock < 0) {
        perror("socket(AF_NETLINK)");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

    if (bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind(AF_NETLINK)");
        close(nl_sock);
        return -1;
    }

    /* Trigger initial dump to populate cache */
    /* (Simplified for now, in a real daemon we'd send RTM_GETADDR) */

    printf("Netlink socket initialized (fd: %d)\n", nl_sock);
    return 0;
}

int hal_netlink_get_fd(void) {
    return nl_sock;
}

void hal_netlink_process(void) {
    char buf[4096];
    struct nlmsghdr *nh;
    ssize_t len;

    len = recv(nl_sock, buf, sizeof(buf), 0);
    if (len < 0) {
        perror("recv(netlink)");
        return;
    }

    for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
        if (nh->nlmsg_type == NLMSG_DONE) break;
        if (nh->nlmsg_type == NLMSG_ERROR) continue;

        if (nh->nlmsg_type == RTM_NEWADDR) {
            struct ifaddrmsg *ifa = NLMSG_DATA(nh);
            struct rtattr *rta = (struct rtattr *)IFA_RTA(ifa);
            int rta_len = IFA_PAYLOAD(nh);

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                if (rta->rta_type == IFA_LOCAL) {
                    int idx = ifa->ifa_index % MAX_INTERFACES;
                    ifaces[idx].ifindex = ifa->ifa_index;
                    ifaces[idx].addr = *(struct in_addr *)RTA_DATA(rta);
                    ifaces[idx].active = true;
                    printf("Netlink: Cache updated for if %d: %s\n", 
                           ifa->ifa_index, inet_ntoa(ifaces[idx].addr));
                }
            }
        }
    }
}

int hal_netlink_get_local_addr(int ifindex, struct in_addr *addr) {
    int idx = ifindex % MAX_INTERFACES;
    if (ifaces[idx].active && ifaces[idx].ifindex == ifindex) {
        *addr = ifaces[idx].addr;
        return 0;
    }
    return -1;
}

int hal_netlink_get_egress_if(struct in_addr *dest, struct in_addr *next_hop) {
    /* Simplified route lookup: for now, assume we can find it or just return a default */
    /* In a real implementation, we'd send RTM_GETROUTE to the kernel */
    (void)dest;
    (void)next_hop;
    return 1; /* Mock ifindex 1 */
}
