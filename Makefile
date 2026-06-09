CC = gcc
CFLAGS = -Wall -Wextra -I./src -I./src/common -I./src/pi
LDFLAGS = 

SRC = src/main.c src/pi/rsvp_dispatcher.c src/pi/rsvp_parser.c src/pi/rsvp_state_db.c src/pi/rsvp_state_machine.c src/pi/label_mgr.c src/pi/rsvp_builder.c src/pi/rsvp_timers.c src/pd/hal_timer_linux.c src/pd/hal_netlink_linux.c
OBJ = $(SRC:.c=.o)
TARGET = rsvp_daemon

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
