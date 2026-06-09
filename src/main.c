#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "pi/rsvp_dispatcher.h"
#include "pi/rsvp_state_db.h"
#include "pi/label_mgr.h"
#include "pi/rsvp_timers.h"

#include "pi/rsvp_state_machine.h"
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    printf("Starting RSVP-TE Daemon...\n");

    rsvp_state_db_init();
    label_mgr_init(10000, 20000);
    rsvp_timer_init();

    if (rsvp_dispatcher_init() < 0) {
        fprintf(stderr, "Failed to initialize RSVP dispatcher\n");
        return EXIT_FAILURE;
    }

    if (argc >= 4) {
        struct in_addr dest, next_hop;
        uint16_t tunnel_id = atoi(argv[2]);
        inet_aton(argv[1], &dest);
        inet_aton(argv[3], &next_hop);
        rsvp_initiate_path(&dest, tunnel_id, &next_hop);
    }

    printf("RSVP-TE Daemon initialized. Entering main loop...\n");
    
    /* For now, just a simple loop or call the dispatcher loop */
    rsvp_dispatcher_run();

    return EXIT_SUCCESS;
}
