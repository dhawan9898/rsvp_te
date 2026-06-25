#include <arpa/inet.h>
#include <signal.h>
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

/* ---- Signal handling ---------------------------------------------------- */

/* Signal handler: safe to call rsvp_dispatcher_stop() because it only writes
 * one volatile sig_atomic_t variable.  Everything else (teardown, logging) is
 * done after rsvp_dispatcher_run() returns in main(), where it is safe. */
static void signal_handler(int signum) {
    (void)signum;
    rsvp_dispatcher_stop();
}

static void install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = signal_handler;

    /* SIGTERM: graceful shutdown (systemd, kill) */
    sigaction(SIGTERM, &sa, NULL);

    /* SIGINT: graceful shutdown (Ctrl-C during dev/test) */
    sigaction(SIGINT, &sa, NULL);

    /* SIGHUP: treat as reload/restart request — for now behaves like SIGTERM.
     * A future version could re-read config and refresh LSPs without full teardown. */
    sigaction(SIGHUP, &sa, NULL);

    /* Ignore SIGPIPE so a broken CLI pipe doesn't kill the daemon. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/* ---- Entry point -------------------------------------------------------- */

int main(void) {
    srand((unsigned int)time(NULL));

#ifdef RSVP_LOGGING_ENABLED
    rsvp_log_init("rsvp_daemon.log");
#endif
    rsvp_set_log_level(LOG_LEVEL_DEBUG);
    LOG_INFO("Starting RSVP-TE Daemon (PID %d)", (int)getpid());

    install_signal_handlers();

    rsvp_state_db_init();
    label_mgr_init(1000, 20000);
    rsvp_timer_init();

    if (rsvp_dispatcher_init() < 0) {
        LOG_ERROR("Failed to initialize RSVP dispatcher");
        return EXIT_FAILURE;
    }

    LOG_INFO("RSVP-TE Daemon initialized. Entering main loop.");

    rsvp_dispatcher_run();

    /* ---- Graceful shutdown ---- */
    LOG_WARN("RSVP-TE Daemon shutting down — sending PathTear/ResvTear for all LSPs");
    rsvp_state_machine_shutdown();

    /* Release state after all PathTear/ResvTear messages have been sent. */
    rsvp_state_db_cleanup();

    LOG_INFO("RSVP-TE Daemon exited cleanly");

#ifdef RSVP_LOGGING_ENABLED
    rsvp_log_close();
#endif

    return EXIT_SUCCESS;
}
