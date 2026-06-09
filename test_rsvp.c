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

/* Mock HAL functions for testing */
int hal_netlink_get_egress_if(struct in_addr *dest, struct in_addr *next_hop) {
    /* Mock: return ifindex 5 and next_hop = dest */
    *next_hop = *dest;
    return 5; 
}

int hal_netlink_get_local_addr(int ifindex, struct in_addr *addr) {
    inet_aton("10.0.0.1", addr);
    return 0;
}

bool hal_netlink_is_local_addr(struct in_addr *addr) {
    struct in_addr local;
    inet_aton("10.0.0.2", &local); /* Fake the destination as local for the test Egress condition */
    return addr->s_addr == local.s_addr;
}

/* Mock timer functions so we don't need real Linux timerfds for the test */
uint32_t hal_timer_add(uint32_t timeout_ms, void* cb, void *data) {
    static uint32_t fake_id = 100;
    return fake_id++;
}
void hal_timer_remove(uint32_t id) {}

/* We will capture the packet sent by rsvp_initiate_path */
static uint8_t captured_packet[2048];
static size_t captured_len = 0;

int rsvp_send_packet(struct in_addr *dest, uint8_t *buffer, size_t len) {
    printf("[TEST] Captured packet sent to %s, length: %zu\n", inet_ntoa(*dest), len);
    memcpy(captured_packet, buffer, len);
    captured_len = len;
    return 0;
}

int main() {
    printf("--- Running RSVP-TE Logic Verification ---\n");
    rsvp_state_db_init();
    label_mgr_init(100, 200);
    
    struct in_addr src, dest;
    inet_aton("10.0.0.1", &src);
    inet_aton("10.0.0.2", &dest);
    
    printf("\n1. Initiating PATH message...\n");
    rsvp_initiate_path(&src, &dest, 1, "test_lsp_01");
    
    if (captured_len > 0) {
        printf("\n2. Parsing the generated PATH message...\n");
        struct rsvp_message_info info;
        memset(&info, 0, sizeof(info));
        
        /* The builder puts the common header at the start of the buffer.
           Normally the socket includes an IP header, but our rsvp_send_packet 
           gets just the RSVP payload. We need to prepend a dummy IP header 
           for rsvp_parse_packet, since it expects an IP header! */
           
        uint8_t pkt_with_ip[2048];
        struct iphdr *ip = (struct iphdr *)pkt_with_ip;
        ip->ihl = 5; /* 20 bytes */
        
        memcpy(pkt_with_ip + 20, captured_packet, captured_len);
        
        if (rsvp_parse_packet(pkt_with_ip, captured_len + 20, &info) == 0) {
            printf("Parse SUCCESS!\n");
            printf("Message Type: %d\n", info.common_hdr->msg_type);
            printf("Tunnel ID: %d\n", info.key.session.tunnel_id);
            printf("Source IP: %s\n", inet_ntoa(info.key.sender.source_addr));
            
            if (info.label_req) {
                printf("LABEL_REQUEST Object found (L3PID: 0x%04x)\n", ntohs(info.label_req->l3pid));
            } else {
                printf("ERROR: LABEL_REQUEST missing!\n");
            }
            
            if (info.tspec) {
                printf("SENDER_TSPEC Object found\n");
            } else {
                printf("ERROR: SENDER_TSPEC missing!\n");
            }
            
            /* Now simulate receiving a RESV */
            printf("\n3. Simulating RESV message reception...\n");
            info.common_hdr->msg_type = RSVP_MSG_RESV; /* Fake it */
            rsvp_handle_message(&info); /* This should trigger RESV logic */
            
        } else {
            printf("Parse FAILED!\n");
        }
    } else {
        printf("No packet was generated!\n");
    }
    
    return 0;
}
