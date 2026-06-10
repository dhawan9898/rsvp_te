CC = gcc
CFLAGS = -Wall -Wextra -I./src -I./src/common -I./src/pi
LDFLAGS = 

COMMON_HDRS = src/common/rsvp_protocol.h src/common/rsvp_log.h
PI_HDRS = src/pi/rsvp_builder.h src/pi/rsvp_dispatcher.h src/pi/rsvp_parser.h src/pi/rsvp_state.h src/pi/rsvp_state_db.h src/pi/rsvp_state_machine.h src/pi/label_mgr.h src/pi/rsvp_timers.h

SRC = src/main.c src/pi/rsvp_dispatcher.c src/pi/rsvp_parser.c src/pi/rsvp_state_db.c src/pi/rsvp_state_machine.c src/pi/label_mgr.c src/pi/rsvp_builder.c src/pi/rsvp_timers.c src/pd/hal_timer_linux.c src/pd/hal_netlink_linux.c src/common/rsvp_log.c
OBJ = $(SRC:.c=.o)
TARGET = rsvp_daemon

TEST_SRC = test_rsvp.c src/pi/rsvp_parser.c src/pi/rsvp_state_db.c src/pi/rsvp_state_machine.c src/pi/label_mgr.c src/pi/rsvp_builder.c src/pi/rsvp_timers.c src/common/rsvp_log.c
TEST_OBJ = $(TEST_SRC:.c=.o)
TEST_TARGET = test_rsvp

all: $(TARGET) $(TEST_TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

$(TEST_TARGET): $(TEST_OBJ)
	$(CC) $(TEST_OBJ) -o $(TEST_TARGET) $(LDFLAGS)

%.o: %.c $(COMMON_HDRS) $(PI_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TEST_OBJ) $(TARGET) $(TEST_TARGET)

.PHONY: all clean
