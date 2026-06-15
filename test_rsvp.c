#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/rsvp_log.h"
#include "pi/label_mgr.h"
#include "pi/rsvp_builder.h"
#include "pi/rsvp_parser.h"
#include "pi/rsvp_state_db.h"
#include "pi/rsvp_state_machine.h"
#include "pi/rsvp_timers.h"

/* Mock HAL functions for testing */
int hal_netlink_get_egress_if(struct in_addr* dest, struct in_addr* next_hop) {
    /* Mock: return ifindex 5 and next_hop = dest */
    *next_hop = *dest;
    return 5;
}

int hal_netlink_get_local_addr(int ifindex, struct in_addr* addr) {
    (void)ifindex;
    inet_aton("10.0.0.1", addr);
    return 0;
}

bool test_is_local = true;

bool hal_netlink_is_local_addr(struct in_addr* addr) {
    (void)addr;
    return test_is_local;
}

int hal_mpls_install(uint32_t in_label, uint32_t out_label, int out_ifindex,
                     struct in_addr* next_hop) {
    printf("[TEST] MPLS Install: in=%u, out=%u, if=%d, next=%s\n", in_label,
           out_label, out_ifindex, next_hop ? inet_ntoa(*next_hop) : "NULL");
    return 0;
}

int hal_mpls_remove(uint32_t in_label) {
    printf("[TEST] MPLS Remove: in=%u\n", in_label);
    return 0;
}

/* Mock timer functions so we don't need real Linux timerfds for the test */
int hal_timer_init(void) {
    return 100; /* Fake FD */
}
void hal_timer_set(uint32_t timeout_ms) { (void)timeout_ms; }
void hal_timer_clear(void) {}

/* We will capture the packet sent by rsvp_initiate_path */
static uint8_t captured_packet[2048];
static size_t captured_len = 0;

rsvp_error_t rsvp_send_packet(struct in_addr* src, struct in_addr* dest, uint8_t* buffer,
                     size_t len, bool use_rao) {
    char src_str[INET_ADDRSTRLEN];
    char dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, src, src_str, sizeof(src_str));
    inet_ntop(AF_INET, dest, dest_str, sizeof(dest_str));
    printf("[TEST] Captured packet sent to %s from %s, length: %zu (RAO: %s)\n",
           dest_str, src_str, len, use_rao ? "on" : "off");
    memcpy(captured_packet, buffer, len);
    captured_len = len;
    return RSVP_SUCCESS;
}

int main() {
    rsvp_log_init("test_rsvp.log");
    rsvp_set_log_level(LOG_LEVEL_DEBUG);
    printf("--- Running RSVP-TE Logic Verification (Logs in test_rsvp.log) ---\n");
    rsvp_state_db_init();
    label_mgr_init(1000, 2000);

    struct in_addr src, dest;
    inet_aton("10.0.0.1", &src);
    inet_aton("10.0.0.2", &dest);

    printf("\n1. Initiating PATH message...\n");
    rsvp_initiate_path(&src, &dest, 1, "test_lsp_01");

    if (captured_len > 0) {
        printf("\n2. Parsing the generated PATH message...\n");
        struct rsvp_message_info info;
        memset(&info, 0, sizeof(info));

        uint8_t pkt_with_ip[2048];
        struct iphdr* ip = (struct iphdr*)pkt_with_ip;
        memset(ip, 0, 20);
        ip->ihl = 5; /* 20 bytes */

        memcpy(pkt_with_ip + 20, captured_packet, captured_len);

        if (rsvp_parse_packet(pkt_with_ip, captured_len + 20, &info) == RSVP_SUCCESS) {
            printf("Parse SUCCESS!\n");
            printf("Message Type: %d\n", info.common_hdr->msg_type);
            printf("Tunnel ID: %d\n", ntohs(info.key.session.tunnel_id));
            printf("Source IP: %s\n", inet_ntoa(info.key.sender.source_addr));

            /* Process the PATH message. Since
               test_is_local is TRUE, this will trigger
               Egress logic and send a RESV upstream. */
            printf("\n--- Processing PATH at Egress ---\n");
            rsvp_handle_message(&info);

            /* Now the 'captured_packet' should contain the RESV message */
            printf("\n--- Processing RESV at Ingress ---\n");
            struct rsvp_message_info resv_info;
            memset(&resv_info, 0, sizeof(resv_info));

            uint8_t resv_pkt_with_ip[2048];
            struct iphdr* resv_ip = (struct iphdr*)resv_pkt_with_ip;
            memset(resv_ip, 0, 20);
            resv_ip->ihl = 5;
            memcpy(resv_pkt_with_ip + 20, captured_packet, captured_len);

            if (rsvp_parse_packet(resv_pkt_with_ip, captured_len + 20,
                                  &resv_info) == RSVP_SUCCESS) {
                printf("RESV Parse SUCCESS!\n");
                rsvp_handle_message(&resv_info);
            } else {
                printf("RESV Parse FAILED!\n");
            }

            /* --- Backup Timer Logic Verification --- */
            printf("\n--- Test: Backup Timer Logic (Transit Node) ---\n");
            
            /* Change mock to Transit node (dest is NOT local) */
            test_is_local = false; 

            /* Test PATH backup */
            captured_len = 0;
            printf("Processing 1st PATH at Transit (New PSB)...\n");
            struct rsvp_message_info path_info;
            memset(&path_info, 0, sizeof(path_info));
            
            uint8_t path_buf[256];
            struct rsvp_builder pb;
            rsvp_builder_init(&pb, path_buf, sizeof(path_buf), RSVP_MSG_PATH);
            struct in_addr t_dest = {0};
            inet_aton("10.0.0.4", &t_dest);
            struct in_addr t_src = {0};
            inet_aton("10.0.0.1", &t_src);

            rsvp_builder_add_session_ipv4(&pb, &t_dest, 100, &t_dest);
            struct rsvp_sender_ipv4 t_sender;
            memset(&t_sender, 0, sizeof(t_sender));
            t_sender.source_addr = t_src;
            t_sender.lsp_id = htons(100);
            rsvp_builder_add_obj(&pb, RSVP_CLASS_SENDER_TEMPLATE, 7, &t_sender, sizeof(t_sender));
            struct in_addr nbr_addr;
            inet_aton("10.0.0.5", &nbr_addr);
            rsvp_builder_add_hop_ipv4(&pb, &nbr_addr, 10);
            rsvp_builder_add_label_request(&pb, 0x0800);
            size_t path_len = rsvp_builder_finalize(&pb);
            
            uint8_t path_pkt_with_ip[256];
            struct iphdr* path_ip = (struct iphdr*)path_pkt_with_ip;
            memset(path_ip, 0, 20);
            path_ip->ihl = 5;
            memcpy(path_pkt_with_ip + 20, path_buf, path_len);
            
            rsvp_parse_packet(path_pkt_with_ip, path_len + 20, &path_info);
            rsvp_handle_message(&path_info);
            if (captured_len > 0) {
                printf("SUCCESS: Sent PATH on NEW PSB\n");
            } else {
                printf("FAILURE: Did not send PATH on NEW PSB\n");
            }

            captured_len = 0;
            printf("Processing 2nd PATH at Transit (Existing PSB)...\n");
            rsvp_handle_message(&path_info);
            if (captured_len > 0) {
                printf("SUCCESS: Sent redundant PATH (State Refreshed)\n");
            } else {
                printf("FAILURE: Did not send PATH refresh for existing PSB\n");
            }

            /* Test RESV backup */
            struct rsvp_message_info resv_info_2;
            memset(&resv_info_2, 0, sizeof(resv_info_2));
            
            uint8_t resv_buf[256];
            struct rsvp_builder rb;
            rsvp_builder_init(&rb, resv_buf, sizeof(resv_buf), RSVP_MSG_RESV);
            rsvp_builder_add_session_ipv4(&rb, &t_dest, 100, &t_dest);
            rsvp_builder_add_hop_ipv4(&rb, &nbr_addr, 10);
            rsvp_builder_add_style(&rb, RSVP_STYLE_FF);
            rsvp_builder_add_obj(&rb, RSVP_CLASS_FILTER_SPEC, 7, &t_sender, sizeof(t_sender));
            rsvp_builder_add_label_ipv4(&rb, 2000);
            size_t resv_len = rsvp_builder_finalize(&rb);

            uint8_t resv_pkt_with_ip_2[256];
            struct iphdr* resv_ip_2 = (struct iphdr*)resv_pkt_with_ip_2;
            memset(resv_ip_2, 0, 20);
            resv_ip_2->ihl = 5;
            memcpy(resv_pkt_with_ip_2 + 20, resv_buf, resv_len);

            captured_len = 0;
            printf("\nProcessing 1st RESV at Transit (New RSB)...\n");
            rsvp_parse_packet(resv_pkt_with_ip_2, resv_len + 20, &resv_info_2);
            rsvp_handle_message(&resv_info_2);
            if (captured_len > 0) {
                printf("SUCCESS: Sent RESV on NEW RSB\n");
            } else {
                printf("FAILURE: Did not send RESV on NEW RSB\n");
            }

            captured_len = 0;
            printf("Processing 2nd RESV at Transit (Existing RSB)...\n");
            rsvp_handle_message(&resv_info_2);
            if (captured_len > 0) {
                printf("SUCCESS: Sent redundant RESV (State Refreshed)\n");
            } else {
                printf("FAILURE: Did not send RESV refresh for existing RSB\n");
            }

            /* --- Tear Message Handling Verification --- */
            printf("\n--- Test: Tear Message Handling ---\n");
            
            /* Test PathTear */
            printf("Processing PathTear for Tunnel 100...\n");
            uint8_t tear_buf[256];
            struct rsvp_builder tb;
            rsvp_builder_init(&tb, tear_buf, sizeof(tear_buf), RSVP_MSG_PATHTEAR);
            rsvp_builder_add_session_ipv4(&tb, &t_dest, 100, &t_dest);
            rsvp_builder_add_hop_ipv4(&tb, &t_src, 1);
            rsvp_builder_add_obj(&tb, RSVP_CLASS_SENDER_TEMPLATE, 7, &t_sender, sizeof(t_sender));
            size_t tear_len = rsvp_builder_finalize(&tb);

            uint8_t tear_pkt_with_ip[256];
            struct iphdr* tear_ip = (struct iphdr*)tear_pkt_with_ip;
            memset(tear_ip, 0, 20);
            tear_ip->ihl = 5;
            tear_ip->saddr = t_src.s_addr;
            tear_ip->daddr = t_dest.s_addr;
            memcpy(tear_pkt_with_ip + 20, tear_buf, tear_len);

            struct rsvp_message_info tear_info;
            memset(&tear_info, 0, sizeof(tear_info));
            rsvp_parse_packet(tear_pkt_with_ip, tear_len + 20, &tear_info);
            
            struct rsvp_psb* psb_to_tear = rsvp_psb_find(&path_info.key);
            if (psb_to_tear) {
                printf("  - PSB exists before PathTear\n");
                rsvp_handle_message(&tear_info);
                if (rsvp_psb_find(&path_info.key) == NULL) {
                    printf("  - SUCCESS: PSB cleaned up after PathTear\n");
                } else {
                    printf("  - FAILURE: PSB still exists after PathTear\n");
                }
            } else {
                printf("  - FAILURE: PSB not found before PathTear\n");
            }

            /* Test ResvTear */
            printf("\nProcessing ResvTear for Tunnel 100...\n");
            
            /* Re-create PSB and RSB for ResvTear test */
            rsvp_handle_message(&path_info);
            rsvp_handle_message(&resv_info_2);

            rsvp_builder_init(&tb, tear_buf, sizeof(tear_buf), RSVP_MSG_RESVTEAR);
            rsvp_builder_add_session_ipv4(&tb, &t_dest, 100, &t_dest);
            rsvp_builder_add_hop_ipv4(&tb, &t_src, 1);
            rsvp_builder_add_style(&tb, RSVP_STYLE_FF);
            rsvp_builder_add_obj(&tb, RSVP_CLASS_FILTER_SPEC, 7, &t_sender, sizeof(t_sender));
            tear_len = rsvp_builder_finalize(&tb);

            memcpy(tear_pkt_with_ip + 20, tear_buf, tear_len);
            memset(&tear_info, 0, sizeof(tear_info));
            rsvp_parse_packet(tear_pkt_with_ip, tear_len + 20, &tear_info);

            struct rsvp_rsb* rsb_to_tear = rsvp_rsb_find(&resv_info_2.key);
            if (rsb_to_tear) {
                printf("  - RSB exists before ResvTear\n");
                rsvp_handle_message(&tear_info);
                if (rsvp_rsb_find(&resv_info_2.key) == NULL) {
                    printf("  - SUCCESS: RSB cleaned up after ResvTear\n");
                } else {
                    printf("  - FAILURE: RSB still exists after ResvTear\n");
                }
            } else {
                printf("  - FAILURE: RSB not found before ResvTear\n");
            }

        } else {
            printf("Parse FAILED!\n");
        }
    } else {
        printf("No packet was generated!\n");
    }

    return 0;
}
