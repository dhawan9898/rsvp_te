/**
 * @file rsvp_cli.c
 * @brief Command Line Interface (CLI) Implementation for RSVP-TE.
 * @details Implements the CLI loop and command handlers to interact with the RSVP-TE state machine and debugging tools.
 */

#include "rsvp_cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "common/rsvp_log.h"
#include "hal/hal_netlink.h"
#include "rsvp_hello.h"
#include "rsvp_if.h"
#include "rsvp_state_db.h"
#include "rsvp_state_machine.h"

/**
 * @brief Print the CLI prompt to standard output.
 * @details Outputs the "rsvp-te>" prompt and flushes the stdout buffer.
 */
static void rsvp_cli_print_prompt(void) {
    printf("rsvp-te> ");
    fflush(stdout);
}

int rsvp_cli_handle_input(int fd) {
    char buf[256];
    
    /* Read user input from the specified file descriptor */
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) return -1;
    if (n == 0) return -1; /* EOF */

    buf[n] = '\0';
    
    /* Strip trailing whitespace, carriage returns, and newlines */
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
        buf[n - 1] = '\0';
        n--;
    }

    /* Process the command based on string matching */
    if (strcmp(buf, "show psb") == 0) {
        rsvp_psb_dump();

    } else if (strcmp(buf, "show rsb") == 0) {
        rsvp_rsb_dump();

    } else if (strcmp(buf, "show mpls routes") == 0) {
        hal_mpls_dump();

    /* ---- RSVP Hello / neighbor commands --------------------------------- */
    } else if (strcmp(buf, "show rsvp neighbors") == 0) {
        rsvp_hello_dump();

    /* ---- RSVP interface commands ---------------------------------------- */
    } else if (strcmp(buf, "show rsvp interfaces") == 0) {
        rsvp_if_dump();

    } else if (strncmp(buf, "show rsvp interface ", 20) == 0) {
        rsvp_if_dump_one(buf + 20);

    } else if (strncmp(buf, "interface ", 10) == 0) {
        /* Format: interface <name> rsvp enable|disable
         *         interface <name> bandwidth <Mbps>
         *         interface <name> reservable-bandwidth <Mbps>
         *         interface <name> hello-interval <ms>
         *         interface <name> rsvp neighbor <neighbor_ip>
         */
        char if_name[IF_NAMESIZE] = {0};
        char subcmd[64] = {0};
        if (sscanf(buf + 10, "%15s %63s", if_name, subcmd) < 2) {
            printf("Usage: interface <name> <subcommand>\n");
            goto done;
        }

        if (strcmp(subcmd, "rsvp") == 0) {
            char action[16] = {0};
            if (sscanf(buf + 10, "%15s rsvp %15s", if_name, action) == 2) {
                if (strcmp(action, "enable") == 0) {
                    if (rsvp_if_enable(if_name))
                        printf("RSVP enabled on %s\n", if_name);
                } else if (strcmp(action, "disable") == 0) {
                    rsvp_if_disable(if_name);
                    printf("RSVP disabled on %s\n", if_name);
                } else if (strcmp(action, "neighbor") == 0) {
                    /* interface <name> rsvp neighbor <ip> */
                    char nbor_str[INET_ADDRSTRLEN] = {0};
                    if (sscanf(buf + 10, "%15s rsvp neighbor %45s", if_name, nbor_str) == 2) {
                        struct in_addr nbor_addr = {0}, local_addr = {0};
                        if (inet_pton(AF_INET, nbor_str, &nbor_addr) != 1) {
                            printf("Invalid IP address: %s\n", nbor_str);
                            goto done;
                        }
                        struct rsvp_if* iface = rsvp_if_get_by_name(if_name);
                        unsigned int idx = (iface && iface->ifindex) ? (unsigned int)iface->ifindex : 0;
                        hal_netlink_get_local_addr((int)idx, &local_addr);
                        struct rsvp_neighbor* n = rsvp_hello_add_neighbor(&nbor_addr, &local_addr, idx);
                        if (n)
                            printf("Tracking RSVP neighbor %s on %s — Hello interval %u ms\n",
                                   nbor_str, if_name, n->hello_interval_ms);
                    } else {
                        printf("Usage: interface <name> rsvp neighbor <ip>\n");
                    }
                } else {
                    printf("Usage: interface <name> rsvp enable|disable|neighbor <ip>\n");
                }
            } else {
                printf("Usage: interface <name> rsvp enable|disable|neighbor <ip>\n");
            }

        } else if (strcmp(subcmd, "bandwidth") == 0) {
            double mbps = 0.0;
            if (sscanf(buf + 10, "%15s bandwidth %lf", if_name, &mbps) == 2) {
                rsvp_if_set_bandwidth(if_name, mbps * 1e6, mbps * 1e6);
                printf("Interface %s: total/reservable bandwidth set to %.2f Mbps\n", if_name, mbps);
            } else {
                printf("Usage: interface <name> bandwidth <Mbps>\n");
            }

        } else if (strcmp(subcmd, "reservable-bandwidth") == 0) {
            double mbps = 0.0;
            if (sscanf(buf + 10, "%15s reservable-bandwidth %lf", if_name, &mbps) == 2) {
                struct rsvp_if* iface = rsvp_if_get_by_name(if_name);
                double total = iface ? iface->total_bw : mbps * 1e6;
                rsvp_if_set_bandwidth(if_name, total, mbps * 1e6);
                printf("Interface %s: reservable bandwidth set to %.2f Mbps\n", if_name, mbps);
            } else {
                printf("Usage: interface <name> reservable-bandwidth <Mbps>\n");
            }

        } else if (strcmp(subcmd, "hello-interval") == 0) {
            unsigned int ms = 0;
            if (sscanf(buf + 10, "%15s hello-interval %u", if_name, &ms) == 2 && ms > 0) {
                /* rsvp_if_enable() finds or creates the entry */
                struct rsvp_if* iface = rsvp_if_enable(if_name);
                if (iface) {
                    iface->hello_interval_ms = ms;
                    printf("Interface %s: Hello interval set to %u ms\n", if_name, ms);
                }
            } else {
                printf("Usage: interface <name> hello-interval <ms>\n");
            }

        } else {
            printf("Unknown sub-command: %s\n", subcmd);
            printf("  interface <name> rsvp enable|disable\n");
            printf("  interface <name> rsvp neighbor <ip>\n");
            printf("  interface <name> bandwidth <Mbps>\n");
            printf("  interface <name> reservable-bandwidth <Mbps>\n");
            printf("  interface <name> hello-interval <ms>\n");
        }

    /* ---- FRR / MBB commands --------------------------------------------- */
    } else if (strcmp(buf, "show rsvp frr") == 0) {
        rsvp_frr_dump();

    } else if (strncmp(buf, "rsvp frr revert ", 16) == 0) {
        unsigned int ifidx = 0;
        if (sscanf(buf + 16, "%u", &ifidx) == 1) {
            rsvp_frr_revert((uint32_t)ifidx);
        } else {
            printf("Usage: rsvp frr revert <ifindex>\n");
        }

    } else if (strncmp(buf, "rsvp mbb ", 9) == 0) {
        /* Format: rsvp mbb <tunnel_id> <old_lsp_id> <new_lsp_id> */
        uint32_t tunnel_id = 0, old_id = 0, new_id = 0;
        if (sscanf(buf + 9, "%u %u %u", &tunnel_id, &old_id, &new_id) == 3) {
            rsvp_error_t rc = rsvp_mbb_start((uint16_t)tunnel_id,
                                              (uint16_t)old_id,
                                              (uint16_t)new_id,
                                              NULL, 0);
            switch (rc) {
                case RSVP_SUCCESS:
                    printf("MBB: Signaling new LSPID %u for TunnelID %u — "
                           "old LSPID %u stays active until RESV arrives.\n",
                           new_id, tunnel_id, old_id);
                    break;
                case RSVP_ERR_NOT_FOUND:
                    printf("MBB error: PSB [TunnelID %u, LSPID %u] not found.\n",
                           tunnel_id, old_id);
                    break;
                case RSVP_ERR_ALREADY_EXISTS:
                    printf("MBB error: LSPID %u already exists for TunnelID %u.\n",
                           new_id, tunnel_id);
                    break;
                case RSVP_ERR_INVALID_PARAM:
                    printf("MBB error: This node is not the ingress for "
                           "TunnelID %u LSPID %u.\n", tunnel_id, old_id);
                    break;
                default:
                    printf("MBB error: rc=%d\n", rc);
                    break;
            }
        } else {
            printf("Usage: rsvp mbb <tunnel_id> <old_lsp_id> <new_lsp_id>\n");
        }

    /* ---- Tunnel commands ------------------------------------------------ */
    } else if (strncmp(buf, "delete tunnel ", 14) == 0) {
        uint32_t tunnel_id = 0, lsp_id = 0;
        if (sscanf(buf + 14, "%u %u", &tunnel_id, &lsp_id) == 2) {
            rsvp_teardown_path((uint16_t)tunnel_id, (uint16_t)lsp_id);
        } else {
            printf("Usage: delete tunnel <tunnel_id> <lsp_id>\n");
        }

    } else if (strncmp(buf, "setup tunnel ", 13) == 0) {
        /* Format: setup tunnel <src_ip> <dest_ip> <tunnel_id> <name> */
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
        printf("  show mpls routes\n");
        printf("  show rsvp neighbors\n");
        printf("  show rsvp interfaces\n");
        printf("  show rsvp interface <name>\n");
        printf("  interface <name> rsvp enable|disable\n");
        printf("  interface <name> rsvp neighbor <ip>\n");
        printf("  interface <name> bandwidth <Mbps>\n");
        printf("  interface <name> reservable-bandwidth <Mbps>\n");
        printf("  interface <name> hello-interval <ms>\n");
        printf("  show rsvp frr\n");
        printf("  rsvp frr revert <ifindex>\n");
        printf("  rsvp mbb <tunnel_id> <old_lsp_id> <new_lsp_id>\n");
        printf("  setup tunnel <src_ip> <dest_ip> <tunnel_id> <name>\n");
        printf("  delete tunnel <tunnel_id> <lsp_id>\n");
    }

done:

    rsvp_cli_print_prompt();
    return 0;
}