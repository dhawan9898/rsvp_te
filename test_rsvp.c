#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "pi/rsvp_state_machine.h"
#include "pi/rsvp_parser.h"
#include "pi/rsvp_state_db.h"
#include "pi/label_mgr.h"
#include "pi/rsvp_timers.h"
#include <stdbool.h>

/* Mock HAL functions for testing */
int hal_netlink_get_egress_if(struct in_addr *dest, struct in_addr *next_hop) {
    /* Mock: return ifindex 5 and next_hop = dest */
    *next_hop = *dest;
    return 5; 
}

int hal_netlink_get_local_addr(int ifindex, struct in_addr *addr) {
    (void)ifindex;
    inet_aton("10.0.0.1", addr);
    return 0;
}

bool hal_netlink_is_local_addr(struct in_addr *addr) {
    struct in_addr local;
    inet_aton("10.0.0.2", &local); /* Fake the destination as local for the test Egress condition */
    return addr->s_addr == local.s_addr;
}

int hal_mpls_install(uint32_t in_label, uint32_t out_label, int out_ifindex, struct in_addr *next_hop) {
    printf("[TEST] MPLS Install: in=%u, out=%u, if=%d, next=%s\n", 
           in_label, out_label, out_ifindex, inet_ntoa(*next_hop));
    return 0;
}

int hal_mpls_remove(uint32_t in_label) {
    printf("[TEST] MPLS Remove: in=%u\n", in_label);
    return 0;
}

/* Mock timer functions so we don't need real Linux timerfds for the test */
uint32_t hal_timer_add(uint32_t timeout_ms, void* cb, void *data) {
    (void)timeout_ms; (void)cb; (void)data;
    static uint32_t fake_id = 100;
    return fake_id++;
}
void hal_timer_remove(uint32_t id) { (void)id; }

/* We will capture the packet sent by rsvp_initiate_path */
static uint8_t captured_packet[2048];
static size_t captured_len = 0;

int rsvp_send_packet(struct in_addr *src, struct in_addr *dest, uint8_t *buffer, size_t len, bool use_rao) {
    char src_str[INET_ADDRSTRLEN];
    char dest_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, src, src_str, sizeof(src_str));
    inet_ntop(AF_INET, dest, dest_str, sizeof(dest_str));
    printf("[TEST] Captured packet sent to %s from %s, length: %zu (RAO: %s)\n", 
           dest_str, src_str, len, use_rao ? "on" : "off");
    memcpy(captured_packet, buffer, len);
    captured_len = len;
    return 0;
}

int main() {
    printf("--- Running RSVP-TE Logic Verification ---\n");
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
        struct iphdr *ip = (struct iphdr *)pkt_with_ip;
        memset(ip, 0, 20);
        ip->ihl = 5; /* 20 bytes */
        
        memcpy(pkt_with_ip + 20, captured_packet, captured_len);
        
        if (rsvp_parse_packet(pkt_with_ip, captured_len + 20, &info) == 0) {
            printf("Parse SUCCESS!\n");
            printf("Message Type: %d\n", info.common_hdr->msg_type);
            printf("Tunnel ID: %d\n", ntohs(info.key.session.tunnel_id));
            printf("Source IP: %s\n", inet_ntoa(info.key.sender.source_addr));
            
            /* Process the PATH message. Since hal_netlink_is_local_addr(10.0.0.2) is TRUE,
               this will trigger Egress logic and send a RESV upstream. */
            printf("\n--- Processing PATH at Egress ---\n");
            rsvp_handle_message(&info);
            
            /* Now the 'captured_packet' should contain the RESV message */
            printf("\n--- Processing RESV at Ingress ---\n");
            struct rsvp_message_info resv_info;
            memset(&resv_info, 0, sizeof(resv_info));
            
            uint8_t resv_pkt_with_ip[2048];
            struct iphdr *resv_ip = (struct iphdr *)resv_pkt_with_ip;
            memset(resv_ip, 0, 20);
            resv_ip->ihl = 5;
            memcpy(resv_pkt_with_ip + 20, captured_packet, captured_len);
            
            if (rsvp_parse_packet(resv_pkt_with_ip, captured_len + 20, &resv_info) == 0) {
                printf("RESV Parse SUCCESS!\n");
                rsvp_handle_message(&resv_info);
            } else {
                printf("RESV Parse FAILED!\n");
            }
            
        } else {
            printf("Parse FAILED!\n");
        }
    } else {
        printf("No packet was generated!\n");
    }
    
    return 0;
}
