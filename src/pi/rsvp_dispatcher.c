/**
 * @file rsvp_dispatcher.c
 * @brief Implementation of the RSVP message dispatcher.
 * @details Handles the main event loop for the RSVP daemon, multiplexing between CLI input, raw RSVP sockets, Netlink sockets, and timers.
 */

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
#include <stdio.h>

#include "common/rsvp_log.h"
#include "hal/hal_netlink.h"
#include "pi/rsvp_timers.h"
#include "rsvp_parser.h"
#include "rsvp_builder.h"
#include "rsvp_state_machine.h"
#include "rsvp_cli.h"

#define RSVP_PROTOCOL 46
#define MAX_RSVP_PACKET_SIZE 4096
#define MAX_FDS 64

static int rsvp_raw_sock = -1;

int rsvp_dispatcher_init(void) {
    int one = 1;

    /* Create a raw socket to send and receive RSVP (protocol 46) packets */
    rsvp_raw_sock = socket(AF_INET, SOCK_RAW, RSVP_PROTOCOL);
    if (rsvp_raw_sock < 0) {
        LOG_ERROR("Failed to create raw RSVP socket: %s", strerror(errno));
        return -1;
    }

    /* Instruct the kernel that we will provide the IP header */
    if (setsockopt(rsvp_raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) <
        0) {
        LOG_ERROR("Failed to set IP_HDRINCL: %s", strerror(errno));
        close(rsvp_raw_sock);
        rsvp_raw_sock = -1;
        return -1;
    }

    /* Request that the kernel passes packets with the IP Router Alert Option to us */
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
    bool poll_stdin = true;

    if (rsvp_raw_sock < 0) return;

    printf("rsvp-te> ");
    fflush(stdout);

    while (1) {
        nfds = 0;

        /* Add STDIN for CLI processing if it is active */
        if (poll_stdin) {
            fds[nfds].fd = STDIN_FILENO;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        /* Add Raw RSVP Socket for incoming packets */
        fds[nfds].fd = rsvp_raw_sock;
        fds[nfds].events = POLLIN;
        nfds++;

        /* Add Netlink Socket for interface and route updates */
        fds[nfds].fd = hal_netlink_get_fd();
        fds[nfds].events = POLLIN;
        nfds++;

        /* Add Timer file descriptors */
        int t_count = rsvp_timer_get_fds(timer_fds, MAX_FDS - nfds);
        for (int i = 0; i < t_count; i++) {
            fds[nfds].fd = timer_fds[i];
            fds[nfds].events = POLLIN;
            nfds++;
        }

        /* Block and wait for events on the configured file descriptors */
        int ret = poll(fds, nfds, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("poll: %s", strerror(errno));
            break;
        }

        /* Process triggered events */
        for (int i = 0; i < nfds; i++) {
            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                if (fds[i].fd == STDIN_FILENO) {
                    LOG_INFO("Dispatcher: STDIN hung up/invalid, disabling CLI input");
                    poll_stdin = false;
                } else {
                    LOG_ERROR("poll event error on fd %d: revents=0x%x", fds[i].fd,
                              fds[i].revents);
                }
                continue;
            }

            if (fds[i].revents & POLLIN) {
                if (fds[i].fd == STDIN_FILENO) {
                    /* Handle command line input */
                    if (rsvp_cli_handle_input(STDIN_FILENO) < 0) {
                        LOG_INFO("Dispatcher: STDIN EOF/error, disabling CLI input");
                        poll_stdin = false;
                    }
                } else if (fds[i].fd == rsvp_raw_sock) {
                    /* Read incoming RSVP packet */
                    uint8_t buffer[MAX_RSVP_PACKET_SIZE];
                    struct sockaddr_in src_addr;
                    socklen_t addr_len = sizeof(src_addr);
                    struct rsvp_message_info info;

                    ssize_t bytes_read =
                        recvfrom(rsvp_raw_sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr*)&src_addr, &addr_len);
                    if (bytes_read > 0) {
                        /* Check for local loopback packets to ignore */
                        if (bytes_read >= (ssize_t)sizeof(struct iphdr)) {
                            struct iphdr* ip = (struct iphdr*)buffer;
                            struct in_addr packet_src;
                            packet_src.s_addr = ip->saddr;

                            if (hal_netlink_is_local_addr(&packet_src)) {
                                /* Drop silently; this packet was sent by us */
                                continue;
                            }
                        }

                        char src_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &src_addr.sin_addr, src_str, sizeof(src_str));
                        LOG_DEBUG("Dispatcher: Received %zd bytes from %s", bytes_read, src_str);

                        memset(&info, 0, sizeof(info));

                        /* Parse and handle the RSVP message */
                        rsvp_error_t err = rsvp_parse_packet(buffer, bytes_read, &info);
                        if (err == RSVP_SUCCESS) {
                            rsvp_handle_message(&info);
                        } else {
                            LOG_WARN("Dispatcher: Failed to parse RSVP packet from %s (Error: %d)", src_str, err);
                            /* TODO: Handle Error message */
                        }
                    } else if (bytes_read < 0 && errno != EINTR) {
                        LOG_ERROR("recvfrom: %s", strerror(errno));
                    }
                } else if (fds[i].fd == hal_netlink_get_fd()) {
                    /* Process netlink events (link/address changes) */
                    hal_netlink_process();
                } else {
                    /* Must be a timer fd */
                    rsvp_timer_handle_exp(fds[i].fd);
                }
            }
        }
    }
}

rsvp_error_t rsvp_send_packet(struct in_addr* src, struct in_addr* dest, uint8_t* buffer,
                     size_t len, bool use_rao) {
    uint8_t packet[MAX_RSVP_PACKET_SIZE];
    struct iphdr* iph = (struct iphdr*)packet;
    struct sockaddr_in dest_addr;
    int optlen = use_rao ? 4 : 0;
    size_t total_len = sizeof(struct iphdr) + optlen + len;

    if (total_len > MAX_RSVP_PACKET_SIZE) {
        LOG_ERROR("Packet too large: %zu", total_len);
        return RSVP_ERR_BUFFER_TOO_SMALL;
    }

    if (rsvp_raw_sock < 0) return RSVP_ERR_SYS;

    memset(packet, 0, total_len);

    /* Construct the IP Header */
    iph->ihl = 5 + (optlen / 4);
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = htons(54321);
    iph->frag_off = 0;

    /* Try to get TTL from RSVP header */
    struct rsvp_common_hdr* rsvp_hdr = (struct rsvp_common_hdr*)buffer;
    iph->ttl = (len >= sizeof(struct rsvp_common_hdr)) ? rsvp_hdr->ttl : 255;

    iph->protocol = RSVP_PROTOCOL;
    iph->saddr = src->s_addr;
    iph->daddr = dest->s_addr;
    
    /* Calculate IP Checksum */
    iph->check = 0;
    iph->check = rsvp_checksum(packet, iph->ihl * 4);

    /* Append the Router Alert Option if requested */
    if (use_rao) {
        uint8_t* options = packet + sizeof(struct iphdr);
        options[0] = 148; /* IPOPT_RA */
        options[1] = 4;   /* length */
        options[2] = 0;   /* value = 0 */
        options[3] = 0;
    }

    /* Copy the RSVP message payload */
    memcpy(packet + (iph->ihl * 4), buffer, len);

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = *dest;

    /* Transmit the raw IP packet */
    ssize_t bytes_sent =
        sendto(rsvp_raw_sock, packet, total_len, 0,
               (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (bytes_sent < 0) {
        LOG_ERROR("sendto to %s error: %s", inet_ntoa(*dest), strerror(errno));
        return RSVP_ERR_SEND_FAILED;
    }

    char dest_str[INET_ADDRSTRLEN];
    char src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, dest, dest_str, sizeof(dest_str));
    inet_ntop(AF_INET, src, src_str, sizeof(src_str));

    LOG_INFO("Sent %zd bytes to %s from %s (Type: %d, TTL: %d, RAO: %s)",
             bytes_sent, dest_str, src_str, rsvp_hdr->msg_type, iph->ttl, use_rao ? "on" : "off");
    return RSVP_SUCCESS;
}
