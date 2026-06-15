#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <time.h>

#include "common/rsvp_log.h"
#include "pi/label_mgr.h"
#include "pi/rsvp_dispatcher.h"
#include "pi/rsvp_state_db.h"
#include "pi/rsvp_state_machine.h"
#include "pi/rsvp_timers.h"

#define MAX_TUNNELS 65536
static uint8_t tunnel_bitmap[MAX_TUNNELS / 8] = {0};

static uint16_t allocate_tunnel_id(void) {
    static uint16_t next_id = 1;
    uint16_t start_id = next_id;
    do {
        if (!(tunnel_bitmap[next_id / 8] & (1 << (next_id % 8)))) {
            tunnel_bitmap[next_id / 8] |= (1 << (next_id % 8));
            uint16_t id = next_id++;
            if (next_id == 0) next_id = 1;
            return id;
        }
        next_id++;
        if (next_id == 0) next_id = 1;
    } while (next_id != start_id);
    return 0; /* Full */
}

int main(int argc, char* argv[]) {
    srand(time(NULL));
    rsvp_set_log_level(LOG_LEVEL_DEBUG);
    LOG_INFO("Starting RSVP-TE Daemon...");

    rsvp_state_db_init();
    label_mgr_init(10000, 20000);
    rsvp_timer_init();

    if (rsvp_dispatcher_init() < 0) {
        LOG_ERROR("Failed to initialize RSVP dispatcher");
        return EXIT_FAILURE;
    }

    if (argc >= 4) {
        struct in_addr src, dest;
        char lsp_name[256];
        memset(lsp_name, 0, sizeof(lsp_name));
        size_t name_len = strlen(argv[3]);
        if (name_len > 255) name_len = 255;
        memcpy(lsp_name, argv[3], name_len);

        inet_aton(argv[1], &src);
        inet_aton(argv[2], &dest);

        uint16_t tunnel_id = allocate_tunnel_id();
        if (tunnel_id == 0) {
            LOG_ERROR("No available tunnel IDs!");
            return EXIT_FAILURE;
        }
        rsvp_initiate_path(&src, &dest, tunnel_id, lsp_name);
    } else if (argc > 1) {
        LOG_ERROR("Usage: %s <src_ip> <dest_ip> <lsp_name>", argv[0]);
        return EXIT_FAILURE;
    }

    LOG_INFO("RSVP-TE Daemon initialized. Entering main loop...");

    /* For now, just a simple loop or call the dispatcher loop */
    rsvp_dispatcher_run();

    return EXIT_SUCCESS;
}
