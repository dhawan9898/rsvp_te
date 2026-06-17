#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/rsvp_log.h"
#include "hal/hal_netlink.h"

#ifndef AF_MPLS
#define AF_MPLS 28
#endif

#define RTA_VIA 18
#define RTA_NEWDST 19
#define MAX_INTERFACES 32

struct interface {
    int ifindex;
    struct in_addr addr;
    bool active;
};

static struct interface ifaces[MAX_INTERFACES];
static int nl_sock = -1;

static int find_iface_slot(int ifindex) {
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (ifaces[i].active && ifaces[i].ifindex == ifindex) {
            return i;
        }
    }
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (!ifaces[i].active) {
            return i;
        }
    }
    return -1;
}

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type, const void *data,
                     int alen) {
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        return -1;
    }
    rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

int hal_netlink_init(void) {
    struct sockaddr_nl sa;

    nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_sock < 0) {
        LOG_ERROR("socket(AF_NETLINK): %s", strerror(errno));
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

    if (bind(nl_sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        LOG_ERROR("bind(AF_NETLINK): %s", strerror(errno));
        close(nl_sock);
        return -1;
    }

    /* Trigger initial dump to populate cache */
    /* (Simplified for now, in a real daemon we'd send RTM_GETADDR) */

    LOG_INFO("Netlink socket initialized (fd: %d)", nl_sock);
    return 0;
}

int hal_netlink_get_fd(void) { return nl_sock; }

void hal_netlink_process(void) {
    char buf[4096];
    struct nlmsghdr* nh;
    ssize_t len;

    len = recv(nl_sock, buf, sizeof(buf), 0);
    if (len < 0) {
        LOG_ERROR("recv(netlink): %s", strerror(errno));
        return;
    }

    for (nh = (struct nlmsghdr*)buf; NLMSG_OK(nh, len);
         nh = NLMSG_NEXT(nh, len)) {
        if (nh->nlmsg_type == NLMSG_DONE) break;
        if (nh->nlmsg_type == NLMSG_ERROR) continue;

        if (nh->nlmsg_type == RTM_NEWADDR) {
            struct ifaddrmsg* ifa = NLMSG_DATA(nh);
            struct rtattr* rta = (struct rtattr*)IFA_RTA(ifa);
            int rta_len = IFA_PAYLOAD(nh);

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                if (rta->rta_type == IFA_LOCAL) {
                    int idx = find_iface_slot(ifa->ifa_index);
                    if (idx < 0) {
                        LOG_INFO(
                            "Netlink: interface cache full, ignoring if %d",
                            ifa->ifa_index);
                        continue;
                    }
                    ifaces[idx].ifindex = ifa->ifa_index;
                    ifaces[idx].addr = *(struct in_addr*)RTA_DATA(rta);
                    ifaces[idx].active = true;
                    LOG_INFO("Netlink: Cache updated for if %d: %s",
                             ifa->ifa_index, inet_ntoa(ifaces[idx].addr));
                }
            }
        }
    }
}

#include <ifaddrs.h>
#include <net/if.h>

int hal_netlink_get_local_addr(int ifindex, struct in_addr* addr) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            if ((int)if_nametoindex(ifa->ifa_name) == ifindex) {
                struct sockaddr_in* s4 = (struct sockaddr_in*)ifa->ifa_addr;
                *addr = s4->sin_addr;
                freeifaddrs(ifaddr);
                return 0;
            }
        }
    }
    freeifaddrs(ifaddr);
    return -1;
}

bool hal_netlink_is_local_addr(struct in_addr* addr) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return false;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* s4 = (struct sockaddr_in*)ifa->ifa_addr;
            if (s4->sin_addr.s_addr == addr->s_addr) {
                freeifaddrs(ifaddr);
                return true;
            }
        }
    }
    freeifaddrs(ifaddr);
    return false;
}

int hal_netlink_get_egress_if(struct in_addr* dest, struct in_addr* next_hop) {
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buf[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_dst_len = 32;

    struct rtattr* rta =
        (struct rtattr*)(((char*)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &dest->s_addr, 4);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_LENGTH(4);

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return -1;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr*)&sa,
               sizeof(sa)) < 0) {
        close(sock);
        return -1;
    }

    char reply[4096];
    ssize_t len = recv(sock, reply, sizeof(reply), 0);
    close(sock);

    if (len < 0) return -1;

    int ifindex = -1;
    *next_hop = *dest;

    struct nlmsghdr* nh;
    for (nh = (struct nlmsghdr*)reply; NLMSG_OK(nh, len);
         nh = NLMSG_NEXT(nh, len)) {
        if (nh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }
        if (nh->nlmsg_type == RTM_NEWROUTE) {
            struct rtmsg* rtm = NLMSG_DATA(nh);
            int rta_len = RTM_PAYLOAD(nh);
            struct rtattr* rtAttr = RTM_RTA(rtm);

            for (; RTA_OK(rtAttr, rta_len);
                 rtAttr = RTA_NEXT(rtAttr, rta_len)) {
                if (rtAttr->rta_type == RTA_OIF) {
                    ifindex = *(int*)RTA_DATA(rtAttr);
                } else if (rtAttr->rta_type == RTA_GATEWAY) {
                    memcpy(&next_hop->s_addr, RTA_DATA(rtAttr),
                           sizeof(next_hop->s_addr));
                }
            }
            if (ifindex >= 0) {
                return ifindex;
            }
        }
    }

    return -1;
}

int hal_mpls_install(uint32_t in_label, uint32_t out_label, int out_ifindex,
                     struct in_addr* next_hop) {
    LOG_INFO("[HAL-Linux] Installing MPLS: in=%u, out=%u, if=%d, next_hop=%s",
             in_label, out_label, out_ifindex, next_hop ? inet_ntoa(*next_hop) : "NULL");

    if (in_label == 0) {
        LOG_WARN("[HAL-Linux] Skipping MPLS install for in_label 0 (ingress IP encap not implemented)");
        return 0;
    }

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buf[512];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    req.nlh.nlmsg_type = RTM_NEWROUTE;
    req.nlh.nlmsg_seq = 2;
    req.nlh.nlmsg_pid = getpid();
    
    req.rtm.rtm_family = AF_MPLS;
    req.rtm.rtm_dst_len = 20;
    req.rtm.rtm_table = RT_TABLE_MAIN;
    req.rtm.rtm_protocol = RTPROT_BOOT;
    req.rtm.rtm_type = RTN_UNICAST;

    /* RTA_DST */
    uint32_t label_dst = htonl(in_label << 12 | 1 << 8); /* BOS=1 */
    addattr_l(&req.nlh, sizeof(req), RTA_DST, &label_dst, sizeof(label_dst));

    /* RTA_OIF */
    addattr_l(&req.nlh, sizeof(req), RTA_OIF, &out_ifindex, sizeof(out_ifindex));

    /* RTA_NEWDST (if out_label != 0) */
    if (out_label != 0) {
        uint32_t label_new = htonl(out_label << 12 | 1 << 8); /* BOS=1 */
        addattr_l(&req.nlh, sizeof(req), RTA_NEWDST, &label_new, sizeof(label_new));
    }

    /* RTA_VIA */
    if (next_hop && next_hop->s_addr != 0) {
        struct {
            unsigned short rtvia_family;
            uint8_t rtvia_addr[4];
        } via;
        via.rtvia_family = AF_INET;
        memcpy(via.rtvia_addr, &next_hop->s_addr, 4);
        addattr_l(&req.nlh, sizeof(req), RTA_VIA, &via, sizeof(via));
    }

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        LOG_ERROR("[HAL-Linux] socket(AF_NETLINK) failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        LOG_ERROR("[HAL-Linux] sendto RTM_NEWROUTE failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

int hal_mpls_remove(uint32_t in_label) {
    LOG_INFO("[HAL-Linux] Removing MPLS: in=%u", in_label);
    
    if (in_label == 0) {
        LOG_WARN("[HAL-Linux] Skipping MPLS remove for in_label 0");
        return 0;
    }

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buf[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_type = RTM_DELROUTE;
    req.nlh.nlmsg_seq = 3;
    req.nlh.nlmsg_pid = getpid();
    
    req.rtm.rtm_family = AF_MPLS;
    req.rtm.rtm_dst_len = 20;

    uint32_t label_dst = htonl(in_label << 12 | 1 << 8);
    addattr_l(&req.nlh, sizeof(req), RTA_DST, &label_dst, sizeof(label_dst));

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return -1;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        LOG_ERROR("[HAL-Linux] sendto RTM_DELROUTE failed: %s", strerror(errno));
    }
    close(sock);
    return 0;
}
