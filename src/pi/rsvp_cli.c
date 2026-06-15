#include "rsvp_cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "common/rsvp_log.h"
#include "rsvp_state_db.h"
#include "rsvp_state_machine.h"

static void rsvp_cli_print_prompt(void) {
    printf("rsvp-te> ");
    fflush(stdout);
}

void rsvp_cli_handle_input(int fd) {
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return;

    buf[n] = '\0';
    
    // Strip trailing newline
    if (buf[n - 1] == '\n') buf[n - 1] = '\0';

    if (strcmp(buf, "show psb") == 0) {
        rsvp_psb_dump();
    } else if (strcmp(buf, "show rsb") == 0) {
        rsvp_rsb_dump();
    } else if (strncmp(buf, "setup tunnel ", 13) == 0) {
        // format: setup tunnel <src_ip> <dest_ip> <tunnel_id> <name>
        char src_str[32], dest_str[32], name[32];
        uint32_t tunnel_id = 0;
        if (sscanf(buf + 13, "%31s %31s %u %31s", src_str, dest_str, &tunnel_id, name) == 4) {
            struct in_addr src, dest;
            if (inet_pton(AF_INET, src_str, &src) && inet_pton(AF_INET, dest_str, &dest)) {
                printf("Initiating tunnel %u to %s...\n", tunnel_id, dest_str);
                rsvp_initiate_path(&src, &dest, tunnel_id, name);
            } else {
                printf("Invalid IP addresses.\n");
            }
        } else {
            printf("Usage: setup tunnel <src_ip> <dest_ip> <tunnel_id> <name>\n");
        }
    } else if (strlen(buf) > 0) {
        printf("Unknown command: %s\n", buf);
        printf("Available commands:\n");
        printf("  show psb\n");
        printf("  show rsb\n");
        printf("  setup tunnel <src_ip> <dest_ip> <tunnel_id> <name>\n");
    }

    rsvp_cli_print_prompt();
}