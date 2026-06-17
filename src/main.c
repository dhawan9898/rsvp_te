#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common/rsvp_log.h"
#include "pi/label_mgr.h"
#include "pi/rsvp_dispatcher.h"
#include "pi/rsvp_state_db.h"
#include "pi/rsvp_state_machine.h"
#include "pi/rsvp_timers.h"

int main() {
    srand(time(NULL));

#ifdef RSVP_LOGGING_ENABLED
    rsvp_log_init("rsvp_daemon.log");
#endif
    rsvp_set_log_level(LOG_LEVEL_DEBUG);
    LOG_INFO("Starting RSVP-TE Daemon...");

    rsvp_state_db_init();
    label_mgr_init(1000, 20000);
    rsvp_timer_init();

    if (rsvp_dispatcher_init() < 0) {
        LOG_ERROR("Failed to initialize RSVP dispatcher");
        return EXIT_FAILURE;
    }

    LOG_INFO("RSVP-TE Daemon initialized. Entering main loop...");

    /* For now, just a simple loop or call the dispatcher loop */
    rsvp_dispatcher_run();

    return EXIT_SUCCESS;
}
