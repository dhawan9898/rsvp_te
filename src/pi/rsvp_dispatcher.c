#include "rsvp_dispatcher.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/rsvp_log.h"
#include "hal/hal_netlink.h"
#include "pi/rsvp_timers.h"
#include "rsvp_parser.h"
#include "rsvp_state_machine.h"

#define RSVP_PROTOCOL 46
#define MAX_RSVP_PACKET_SIZE 4096
#define MAX_FDS 64

static int rsvp_raw_sock = -1;

int rsvp_dispatcher_init(void) {
    int one = 1;
    rsvp_raw_sock = socket(AF_INET, SOCK_RAW, RSVP_PROTOCOL);
    if (rsvp_raw_sock < 0) {
        LOG_ERROR("Failed to create raw RSVP socket: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(rsvp_raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) <
        0) {
        LOG_ERROR("Failed to set IP_HDRINCL: %s", strerror(errno));
        close(rsvp_raw_sock);
        rsvp_raw_sock = -1;
        return -1;
    }

    if (setsockopt(rsvp_raw_sock, IPPROTO_IP, IP_ROUTER_ALERT, &one,
                   sizeof(one)) < 0) {
        LOG_ERROR("Failed to set IP_ROUTER_ALERT: %s", strerror(errno));
    }

    if (hal_netlink_init() < 0) {
        return -1;
    }

    LOG_INFO("Raw RSVP socket created (fd: %d) with IP_HDRINCL", rsvp_raw_sock);
    return 0;
}

void rsvp_dispatcher_run(void) {
    struct pollfd fds[MAX_FDS];
    int nfds = 0;
    int timer_fds[MAX_FDS];

    if (rsvp_raw_sock < 0) return;

    while (1) {
        nfds = 0;

        /* Raw RSVP Socket */
        fds[nfds].fd = rsvp_raw_sock;
        fds[nfds].events = POLLIN;
        nfds++;

        /* Netlink Socket */
        fds[nfds].fd = hal_netlink_get_fd();
        fds[nfds].events = POLLIN;
        nfds++;

        /* Timer fds */
        int t_count = rsvp_timer_get_fds(timer_fds, MAX_FDS - nfds);
        for (int i = 0; i < t_count; i++) {
            fds[nfds].fd = timer_fds[i];
            fds[nfds].events = POLLIN;
            nfds++;
        }

        int ret = poll(fds, nfds, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("poll: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                LOG_ERROR("poll event error on fd %d: revents=0x%x", fds[i].fd,
                          fds[i].revents);
                continue;
            }

            if (fds[i].revents & POLLIN) {
                if (fds[i].fd == rsvp_raw_sock) {
                    uint8_t buffer[MAX_RSVP_PACKET_SIZE];
                    struct sockaddr_in src_addr;
                    socklen_t addr_len = sizeof(src_addr);
                    struct rsvp_message_info info;

                    ssize_t bytes_read =
                        recvfrom(rsvp_raw_sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr*)&src_addr, &addr_len);
                    if (bytes_read > 0) {
                        memset(&info, 0, sizeof(info));
                        if (rsvp_parse_packet(buffer, bytes_read, &info) == RSVP_SUCCESS) {
                            rsvp_handle_message(&info);
                        }
                    } else if (bytes_read < 0 && errno != EINTR) {
                        LOG_ERROR("recvfrom: %s", strerror(errno));
                    }
                } else if (fds[i].fd == hal_netlink_get_fd()) {
                    hal_netlink_process();
                } else {
                    /* Must be a timer fd */
                    rsvp_timer_handle_exp(fds[i].fd);
                }
            }
        }
    }
}

int rsvp_send_packet(struct in_addr* src, struct in_addr* dest, uint8_t* buffer,
                     size_t len, bool use_rao) {
    uint8_t packet[MAX_RSVP_PACKET_SIZE];
    struct iphdr* iph = (struct iphdr*)packet;
    struct sockaddr_in dest_addr;
    int optlen = use_rao ? 4 : 0;
    size_t total_len = sizeof(struct iphdr) + optlen + len;

    if (total_len > MAX_RSVP_PACKET_SIZE) {
        LOG_ERROR("Packet too large: %zu", total_len);
        return -1;
    }

    if (rsvp_raw_sock < 0) return -1;

    memset(packet, 0, total_len);

    iph->ihl = 5 + (optlen / 4);
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = 0;
    iph->frag_off = 0;

    /* Try to get TTL from RSVP header */
    struct rsvp_common_hdr* rsvp_hdr = (struct rsvp_common_hdr*)buffer;
    iph->ttl = (len >= sizeof(struct rsvp_common_hdr)) ? rsvp_hdr->ttl : 255;

    iph->protocol = RSVP_PROTOCOL;
    iph->saddr = src->s_addr;
    iph->daddr = dest->s_addr;
    iph->check = 0; /* Kernel will fill */

    if (use_rao) {
        uint8_t* options = packet + sizeof(struct iphdr);
        options[0] = 148; /* RFC 2113: Router Alert Option */
        options[1] = 4;
        options[2] = 0;
        options[3] = 0;
    }

    memcpy(packet + (iph->ihl * 4), buffer, len);

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = *dest;

    ssize_t bytes_sent =
        sendto(rsvp_raw_sock, packet, total_len, 0,
               (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (bytes_sent < 0) {
        LOG_ERROR("sendto error: %s", strerror(errno));
        return -1;
    }

    LOG_INFO("Sent %zd bytes to %s from %s (RAO: %s)", bytes_sent,
             inet_ntoa(*dest), inet_ntoa(*src), use_rao ? "on" : "off");
    return 0;
}
