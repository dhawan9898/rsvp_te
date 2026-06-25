CC     = gcc
CFLAGS = -Wall -Wextra -I./src -I./src/common -I./src/pi -I./wheel_timer -I./tests
LDFLAGS = -lpthread -lm

# Enable logging by default. Use DISABLE_LOGS=1 to disable.
ifneq ($(DISABLE_LOGS), 1)
	CFLAGS += -DRSVP_LOGGING_ENABLED
endif

COMMON_HDRS = src/common/rsvp_protocol.h src/common/rsvp_log.h src/common/rsvp_error.h \
              wheel_timer/wheel_timer.h wheel_timer/list.h
PI_HDRS     = src/pi/rsvp_builder.h src/pi/rsvp_dispatcher.h src/pi/rsvp_parser.h \
              src/pi/rsvp_state.h src/pi/rsvp_state_db.h src/pi/rsvp_state_machine.h \
              src/pi/label_mgr.h src/pi/rsvp_timers.h src/pi/rsvp_cli.h \
              src/pi/rsvp_hello.h src/pi/rsvp_if.h

# --- Daemon -------------------------------------------------------------------
SRC    = src/main.c src/pi/rsvp_dispatcher.c src/pi/rsvp_parser.c \
         src/pi/rsvp_state_db.c src/pi/rsvp_state_machine.c src/pi/label_mgr.c \
         src/pi/rsvp_builder.c src/pi/rsvp_timers.c src/pi/rsvp_cli.c \
         src/pi/rsvp_hello.c src/pi/rsvp_if.c \
         src/pd/hal_timer_linux.c src/pd/hal_netlink_linux.c \
         src/common/rsvp_log.c wheel_timer/wheel_timer.c
OBJ    = $(SRC:.c=.o)
TARGET = rsvp_daemon

# --- Unit / functional test suite --------------------------------------------
# Common PI sources shared by every unit test binary (no platform-dependent PD files)
_PI_SRCS = src/pi/rsvp_parser.c src/pi/rsvp_state_db.c src/pi/rsvp_state_machine.c \
           src/pi/label_mgr.c src/pi/rsvp_builder.c src/pi/rsvp_timers.c \
           src/pi/rsvp_hello.c src/pi/rsvp_if.c \
           src/common/rsvp_log.c wheel_timer/wheel_timer.c \
           tests/mocks.c

UNIT_DIR     = tests
UNIT_TARGETS = $(UNIT_DIR)/test_builder \
               $(UNIT_DIR)/test_parser \
               $(UNIT_DIR)/test_state_db \
               $(UNIT_DIR)/test_label_mgr \
               $(UNIT_DIR)/test_if \
               $(UNIT_DIR)/test_hello \
               $(UNIT_DIR)/test_state_machine \
               $(UNIT_DIR)/test_mbb_frr

# builder — only needs rsvp_builder.c (no state machine, no mocks)
$(UNIT_DIR)/test_builder: $(UNIT_DIR)/test_builder.c src/pi/rsvp_builder.c \
                           src/common/rsvp_log.c wheel_timer/wheel_timer.c \
                           $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) $< src/pi/rsvp_builder.c src/common/rsvp_log.c \
	    wheel_timer/wheel_timer.c -o $@ $(LDFLAGS)

# parser — needs builder (to construct test packets) + rsvp_state_db for type defs
$(UNIT_DIR)/test_parser: $(UNIT_DIR)/test_parser.c src/pi/rsvp_parser.c \
                          src/pi/rsvp_builder.c src/pi/rsvp_state_db.c \
                          src/pi/rsvp_timers.c src/common/rsvp_log.c \
                          wheel_timer/wheel_timer.c \
                          tests/mocks.c $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) $< src/pi/rsvp_parser.c src/pi/rsvp_builder.c \
	    src/pi/rsvp_state_db.c src/pi/rsvp_timers.c \
	    src/common/rsvp_log.c wheel_timer/wheel_timer.c tests/mocks.c \
	    -o $@ $(LDFLAGS)

# state_db — minimal: only the DB module
$(UNIT_DIR)/test_state_db: $(UNIT_DIR)/test_state_db.c src/pi/rsvp_state_db.c \
                            src/pi/rsvp_timers.c src/common/rsvp_log.c \
                            wheel_timer/wheel_timer.c \
                            tests/mocks.c $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) $< src/pi/rsvp_state_db.c src/pi/rsvp_timers.c \
	    src/common/rsvp_log.c wheel_timer/wheel_timer.c tests/mocks.c \
	    -o $@ $(LDFLAGS)

# label_mgr — standalone, no mocks needed
$(UNIT_DIR)/test_label_mgr: $(UNIT_DIR)/test_label_mgr.c src/pi/label_mgr.c \
                             src/common/rsvp_log.c wheel_timer/wheel_timer.c \
                             $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) $< src/pi/label_mgr.c src/common/rsvp_log.c \
	    wheel_timer/wheel_timer.c -o $@ $(LDFLAGS)

# rsvp_if — only the IF module; no mocks needed
$(UNIT_DIR)/test_if: $(UNIT_DIR)/test_if.c src/pi/rsvp_if.c \
                     src/common/rsvp_log.c wheel_timer/wheel_timer.c \
                     $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) $< src/pi/rsvp_if.c src/common/rsvp_log.c \
	    wheel_timer/wheel_timer.c -o $@ $(LDFLAGS)

# rsvp_hello — needs builder + timers; rsvp_frr_trigger stub defined in test file
$(UNIT_DIR)/test_hello: $(UNIT_DIR)/test_hello.c src/pi/rsvp_hello.c \
                         src/pi/rsvp_builder.c src/pi/rsvp_timers.c \
                         src/common/rsvp_log.c wheel_timer/wheel_timer.c \
                         tests/mocks.c $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) $< src/pi/rsvp_hello.c src/pi/rsvp_builder.c \
	    src/pi/rsvp_timers.c src/common/rsvp_log.c \
	    wheel_timer/wheel_timer.c tests/mocks.c \
	    -o $@ $(LDFLAGS)

# state_machine — full PI stack, mocks replace PD + dispatcher
$(UNIT_DIR)/test_state_machine: $(UNIT_DIR)/test_state_machine.c $(_PI_SRCS) \
                                 $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) $< $(_PI_SRCS) -o $@ $(LDFLAGS)

# MBB + FRR — same full PI stack
$(UNIT_DIR)/test_mbb_frr: $(UNIT_DIR)/test_mbb_frr.c $(_PI_SRCS) \
                           $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) $< $(_PI_SRCS) -o $@ $(LDFLAGS)

# --- Phony targets -----------------------------------------------------------
all: $(TARGET)

tests: $(UNIT_TARGETS)

check: $(UNIT_TARGETS)
	@echo ""
	@echo "=========================================="
	@echo " Running RSVP-TE unit test suite"
	@echo "=========================================="
	@pass=0; fail=0; \
	for t in $(UNIT_TARGETS); do \
	    echo ""; echo "--- $$t ---"; \
	    if ./$$t; then pass=$$((pass+1)); else fail=$$((fail+1)); fi; \
	done; \
	echo ""; echo "=========================================="; \
	echo " Suite: $$pass passed, $$fail failed"; \
	echo "=========================================="; \
	test $$fail -eq 0

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET) \
	      $(UNIT_TARGETS) tests/test_state_machine.log tests/test_mbb_frr.log

.PHONY: all tests check clean
