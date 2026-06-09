#include "rsvp_dispatcher.h"
#include "rsvp_parser.h"
#include "rsvp_state_machine.h"
#include "hal/hal_netlink.h"
#include "pi/rsvp_timers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>

#define RSVP_PROTOCOL 46
#define MAX_RSVP_PACKET_SIZE 4096
#define MAX_FDS 64

static int rsvp_raw_sock = -1;

int rsvp_dispatcher_init(void) {
    rsvp_raw_sock = socket(AF_INET, SOCK_RAW, RSVP_PROTOCOL);
    if (rsvp_raw_sock < 0) {
        perror("Failed to create raw RSVP socket");
        return -1;
    }

    if (hal_netlink_init() < 0) {
        return -1;
    }

    printf("Raw RSVP socket created (fd: %d)\n", rsvp_raw_sock);
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
            perror("poll");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (fds[i].revents & POLLIN) {
                if (fds[i].fd == rsvp_raw_sock) {
                    uint8_t buffer[MAX_RSVP_PACKET_SIZE];
                    struct sockaddr_in src_addr;
                    socklen_t addr_len = sizeof(src_addr);
                    struct rsvp_message_info info;

                    ssize_t bytes_read = recvfrom(rsvp_raw_sock, buffer, sizeof(buffer), 0,
                                                  (struct sockaddr *)&src_addr, &addr_len);
                    if (bytes_read > 0) {
                        memset(&info, 0, sizeof(info));
                        if (rsvp_parse_packet(buffer, bytes_read, &info) == 0) {
                            rsvp_handle_message(&info);
                        }
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

int rsvp_send_packet(struct in_addr *dest, uint8_t *buffer, size_t len) {
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = *dest;

    if (rsvp_raw_sock < 0) return -1;

    ssize_t bytes_sent = sendto(rsvp_raw_sock, buffer, len, 0,
                                (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (bytes_sent < 0) {
        perror("sendto error");
        return -1;
    }

    printf("Sent %zd bytes to %s\n", bytes_sent, inet_ntoa(*dest));
    return 0;
}
